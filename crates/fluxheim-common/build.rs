fn main() {
    // Cargo supplies OUT_DIR to bind test-only re-execution to this build's
    // profile directory, including custom target directories and profiles.
    println!("cargo:rerun-if-changed=build.rs");
}
