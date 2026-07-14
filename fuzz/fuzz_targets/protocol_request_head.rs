#![no_main]

use fluxheim_protocol::{Http1HeadLimits, parse_http1_request_head};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = Http1HeadLimits {
        max_head_bytes: 64 * 1024,
        max_header_count: 128,
        max_header_line_bytes: 8 * 1024,
        max_start_line_bytes: 8 * 1024,
    };
    let _ = parse_http1_request_head(data, limits);
});
