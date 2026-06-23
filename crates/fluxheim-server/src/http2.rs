use std::time::Duration;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DownstreamHttp2Policy {
    max_header_list_size: u32,
    max_header_count: usize,
    max_uri_bytes: usize,
    max_body_bytes: usize,
    request_body_timeout: Duration,
    response_body_timeout: Duration,
    handler_timeout: Duration,
    response_write_lifetime: Duration,
    max_concurrent_streams: u32,
    initial_window_size: u32,
    max_frame_size: u32,
    max_send_buffer_size: usize,
    max_pending_accept_reset_streams: usize,
}

impl Default for DownstreamHttp2Policy {
    fn default() -> Self {
        Self {
            max_header_list_size: 64 * 1024,
            max_header_count: 100,
            max_uri_bytes: 8 * 1024,
            max_body_bytes: 16 * 1024 * 1024,
            request_body_timeout: Duration::from_secs(30),
            response_body_timeout: Duration::from_secs(30),
            handler_timeout: Duration::from_secs(30),
            response_write_lifetime: Duration::from_secs(30),
            max_concurrent_streams: 32,
            initial_window_size: 64 * 1024,
            max_frame_size: 16 * 1024,
            max_send_buffer_size: 256 * 1024,
            max_pending_accept_reset_streams: 8,
        }
    }
}

impl DownstreamHttp2Policy {
    pub fn from_server_limits(limits: fluxheim_config::ServerLimitsConfig) -> Self {
        Self {
            max_header_list_size: limits
                .max_request_header_bytes
                .as_u64()
                .min(u32::MAX as u64) as u32,
            max_header_count: limits.max_request_headers,
            max_uri_bytes: limits.max_uri_bytes.as_u64().min(usize::MAX as u64) as usize,
            max_body_bytes: limits
                .max_request_body_bytes
                .as_u64()
                .min(usize::MAX as u64) as usize,
            ..Default::default()
        }
    }

    pub const fn max_header_list_size(&self) -> u32 {
        self.max_header_list_size
    }

    pub const fn with_request_body_timeout(mut self, timeout: Duration) -> Self {
        self.request_body_timeout = timeout;
        self
    }

    pub const fn with_response_body_timeout(mut self, timeout: Duration) -> Self {
        self.response_body_timeout = timeout;
        self
    }

    #[cfg(test)]
    pub const fn with_initial_window_size(mut self, initial_window_size: u32) -> Self {
        self.initial_window_size = initial_window_size;
        self
    }

    pub const fn max_header_count(&self) -> usize {
        self.max_header_count
    }

    pub const fn max_uri_bytes(&self) -> usize {
        self.max_uri_bytes
    }

    pub const fn max_body_bytes(&self) -> usize {
        self.max_body_bytes
    }

    pub const fn request_body_timeout(&self) -> Duration {
        self.request_body_timeout
    }

    pub const fn response_body_timeout(&self) -> Duration {
        self.response_body_timeout
    }

    pub const fn handler_timeout(&self) -> Duration {
        self.handler_timeout
    }

    pub const fn with_handler_timeout(mut self, timeout: Duration) -> Self {
        self.handler_timeout = timeout;
        self
    }

    pub const fn response_write_lifetime(&self) -> Duration {
        self.response_write_lifetime
    }

    pub const fn with_response_write_lifetime(mut self, lifetime: Duration) -> Self {
        self.response_write_lifetime = lifetime;
        self
    }

    pub const fn max_concurrent_streams(&self) -> u32 {
        self.max_concurrent_streams
    }

    pub(crate) const fn with_max_concurrent_streams(mut self, streams: u32) -> Self {
        self.max_concurrent_streams = streams;
        self
    }

    pub const fn initial_window_size(&self) -> u32 {
        self.initial_window_size
    }

    pub const fn max_frame_size(&self) -> u32 {
        self.max_frame_size
    }

    pub const fn max_send_buffer_size(&self) -> usize {
        self.max_send_buffer_size
    }

    pub const fn max_pending_accept_reset_streams(&self) -> usize {
        self.max_pending_accept_reset_streams
    }
}
