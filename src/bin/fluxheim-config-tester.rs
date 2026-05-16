#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

fn main() {
    if let Err(error) = fluxheim::config_tester::run_from_env() {
        eprintln!("fluxheim-config-tester: {error}");
        std::process::exit(1);
    }
}
