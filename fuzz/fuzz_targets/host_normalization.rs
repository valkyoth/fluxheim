#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let input = String::from_utf8_lossy(data);
    let normalized = fluxheim::config::normalize_host(&input);

    if let Some(host) = normalized {
        assert!(!host.is_empty());
        assert!(!host.starts_with('.'));
        assert!(!host.contains('*'));
        assert!(!host.contains('/'));
        assert!(!host.contains('\\'));
        assert!(!host.contains('?'));
        assert!(!host.contains('#'));
        assert!(!host.contains('@'));
        assert!(!host.chars().any(|ch| ch.is_whitespace() || ch.is_control()));
        assert_eq!(host, host.to_ascii_lowercase());
    }
});
