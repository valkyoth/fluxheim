#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 128 * 1024 {
        return;
    }
    let _ = fluxheim_php_fpm::parse_php_response(data, 128 * 1024, 64 * 1024);
});
