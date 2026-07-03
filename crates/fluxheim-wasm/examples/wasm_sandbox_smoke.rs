use std::fs;
use std::process::ExitCode;
use std::time::Duration;

use fluxheim_wasm::{FluxWasmRuntime, WasmExecutionError, WasmSandboxLimits, load_plugin_file};

fn main() -> ExitCode {
    match run() {
        Ok(()) => {
            println!("wasm sandbox smoke: ok");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("wasm sandbox smoke failed: {error}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!("fluxheim-wasm-smoke-{}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root)?;
    let plugin = root.join("decision.wasm");
    fs::write(
        &plugin,
        wat::parse_str(r#"(module (func (export "decision") (result i32) i32.const 42))"#)?,
    )?;

    let limits = WasmSandboxLimits {
        fuel: 50_000,
        timeout: Duration::from_millis(100),
        ..WasmSandboxLimits::default()
    };
    let loaded = load_plugin_file(&plugin, std::slice::from_ref(&root), limits)?;
    let runtime = FluxWasmRuntime::new(limits)?;
    let outcome = runtime.run_i32_no_args(&loaded, "decision")?;
    if outcome.result != 42 {
        return Err(format!("expected decision 42, got {}", outcome.result).into());
    }
    if outcome.plugin_sha256.len() != 64 {
        return Err("plugin hash was not recorded".into());
    }

    let spinner = root.join("spin.wasm");
    fs::write(
        &spinner,
        wat::parse_str(
            r#"
            (module
              (func (export "spin") (result i32)
                (loop br 0)
                i32.const 0))
            "#,
        )?,
    )?;
    let limited = WasmSandboxLimits {
        fuel: 500,
        timeout: Duration::from_millis(100),
        ..WasmSandboxLimits::default()
    };
    let loaded_spinner = load_plugin_file(&spinner, std::slice::from_ref(&root), limited)?;
    let runtime = FluxWasmRuntime::new(limited)?;
    match runtime.run_i32_no_args(&loaded_spinner, "spin") {
        Err(WasmExecutionError::Trap(_)) => {}
        Ok(_) => return Err("fuel exhaustion plugin unexpectedly completed".into()),
        Err(error) => return Err(format!("expected trap for fuel exhaustion, got {error}").into()),
    }

    fs::remove_dir_all(&root)?;
    Ok(())
}
