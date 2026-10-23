#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

fn main() {
    if let Err(error) = fluxheim_common::fatal::disable_memory_dumps() {
        eprintln!("fluxheim: unable to disable memory dumps: {error}");
        std::process::exit(1);
    }
    if let Err(error) = fluxheim::run() {
        eprintln!("fluxheim: {error}");
        std::process::exit(1);
    }
}
