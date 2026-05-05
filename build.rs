fn main() {
    let tls_backends = [
        ("tls-rustls", "CARGO_FEATURE_TLS_RUSTLS"),
        ("tls-openssl", "CARGO_FEATURE_TLS_OPENSSL"),
        ("tls-boringssl", "CARGO_FEATURE_TLS_BORINGSSL"),
        ("tls-s2n", "CARGO_FEATURE_TLS_S2N"),
    ]
    .into_iter()
    .filter_map(|(name, env)| std::env::var_os(env).map(|_| name))
    .collect::<Vec<_>>();

    if tls_backends.len() > 1 {
        fail(&format!(
            "select only one Fluxheim TLS backend feature: tls-rustls, tls-openssl, tls-boringssl, or tls-s2n; selected {}",
            tls_backends.join(", ")
        ));
    }

    let privacy_mode = std::env::var_os("CARGO_FEATURE_PRIVACY_MODE").is_some();
    if privacy_mode && std::env::var_os("CARGO_FEATURE_CACHE").is_some() {
        fail(
            "privacy-mode cannot be combined with the cache feature; build with --no-default-features --features profile-privacy or select proxy,web,tls-*,privacy-mode explicitly",
        );
    }

    if privacy_mode && std::env::var_os("CARGO_FEATURE_METRICS").is_some() {
        fail(
            "privacy-mode cannot be combined with metrics; zero-retention builds must not compile request metrics",
        );
    }
}

fn fail(message: &str) -> ! {
    eprintln!("{message}");
    std::process::exit(1);
}
