#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

fn main() {
    if let Err(error) = fluxheim::acme_companion::run_from_env() {
        eprintln!("fluxheim-acme: {error}");
        std::process::exit(1);
    }
}
