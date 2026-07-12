use std::fmt::Write as _;
use std::path::Path;
use std::process::ExitCode;

use sha2::{Digest as _, Sha256};

const OUTPUT_DIR: &str = "target/wasm-policy-examples";
const POLICY_SOURCES: &[(&str, &str)] = &[
    (
        "irules-access-policy",
        include_str!("../../../examples/wasm/irules-access-policy.wat"),
    ),
    (
        "openresty-header-policy",
        include_str!("../../../examples/wasm/openresty-header-policy.wat"),
    ),
    (
        "haproxy-spoe-routing-policy",
        include_str!("../../../examples/wasm/haproxy-spoe-routing-policy.wat"),
    ),
    (
        "cache-lookup-policy",
        include_str!("../../../examples/wasm/cache-lookup-policy.wat"),
    ),
    (
        "cache-store-policy",
        include_str!("../../../examples/wasm/cache-store-policy.wat"),
    ),
];

fn main() -> ExitCode {
    match build_examples() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("wasm policy example build failed: {error}");
            ExitCode::FAILURE
        }
    }
}

fn build_examples() -> Result<(), Box<dyn std::error::Error>> {
    let output = Path::new(OUTPUT_DIR);
    std::fs::create_dir_all(output)?;
    let mut checksums = String::new();

    for (name, source) in POLICY_SOURCES {
        let bytes = wat::parse_str(source)?;
        let file_name = format!("{name}.wasm");
        std::fs::write(output.join(&file_name), &bytes)?;
        let digest = Sha256::digest(&bytes);
        for byte in digest {
            write!(&mut checksums, "{byte:02x}")?;
        }
        writeln!(&mut checksums, "  {file_name}")?;
    }

    std::fs::write(output.join("SHA256SUMS"), checksums)?;
    println!("built Wasm policy examples in {OUTPUT_DIR}");
    Ok(())
}
