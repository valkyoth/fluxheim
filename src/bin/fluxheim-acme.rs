#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

fn main() {
    if fluxheim_common::fatal::disable_memory_dumps().is_err() {
        // Still potentially dumpable: never block on diagnostics before exit.
        std::process::exit(1);
    }
    if let Err(error) = fluxheim::acme_companion::run_from_env() {
        eprintln!("fluxheim-acme: {error}");
        std::process::exit(1);
    }
}
