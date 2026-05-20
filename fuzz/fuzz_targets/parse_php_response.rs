#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 128 * 1024 {
        return;
    }
    let _ = fluxheim::proxy::fuzz_parse_php_response(data);
});
