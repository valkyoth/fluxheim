#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DownstreamHttp2Policy {
    max_header_list_size: u32,
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
            max_concurrent_streams: 32,
            initial_window_size: 64 * 1024,
            max_frame_size: 16 * 1024,
            max_send_buffer_size: 256 * 1024,
            max_pending_accept_reset_streams: 8,
        }
    }
}

impl DownstreamHttp2Policy {
    pub const fn max_header_list_size(&self) -> u32 {
        self.max_header_list_size
    }

    pub const fn max_concurrent_streams(&self) -> u32 {
        self.max_concurrent_streams
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
