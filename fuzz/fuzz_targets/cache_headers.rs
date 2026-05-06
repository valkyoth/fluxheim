#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let split = data.len() / 2;
    let first = String::from_utf8_lossy(&data[..split]);
    let second = String::from_utf8_lossy(&data[split..]);

    let single = fluxheim::cache_headers::request_forces_cache_refresh(Some(&first), Some(&second));
    let repeated = fluxheim::cache_headers::request_values_force_cache_refresh(
        [first.as_ref()],
        [second.as_ref()],
    );
    assert_eq!(single, repeated);

    let _ = fluxheim::cache_headers::response_values_forbid_shared_cache([
        first.as_ref(),
        second.as_ref(),
    ]);
});
