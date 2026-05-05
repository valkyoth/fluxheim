fn main() {
    if let Err(error) = fluxheim::run() {
        eprintln!("fluxheim: {error}");
        std::process::exit(1);
    }
}
