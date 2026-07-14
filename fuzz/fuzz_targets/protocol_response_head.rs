#![no_main]

use fluxheim_protocol::{Http1HeadLimits, parse_http1_response_head};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = parse_http1_response_head(data, Http1HeadLimits::default());
});
