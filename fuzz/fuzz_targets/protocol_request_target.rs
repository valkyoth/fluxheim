#![no_main]

use fluxheim_protocol::http1_request_target;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&selector, target)) = data.split_first() else {
        return;
    };
    let Ok(target) = std::str::from_utf8(target) else {
        return;
    };
    let method = match selector % 4 {
        0 => "GET",
        1 => "POST",
        2 => "OPTIONS",
        _ => "CONNECT",
    };
    let _ = http1_request_target(method, target);
});
