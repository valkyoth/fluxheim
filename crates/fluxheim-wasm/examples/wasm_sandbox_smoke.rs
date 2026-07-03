use std::fs;
use std::process::ExitCode;
use std::time::Duration;

use fluxheim_wasm::{
    FluxWasmRuntime, WasmExecutionError, WasmManifestError, WasmPluginAbi, WasmPluginFailMode,
    WasmPluginManifest, WasmPluginPhase, WasmSandboxLimits, load_plugin_file,
    load_plugin_from_manifest, validate_plugin_manifest,
};

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
    let manifest = WasmPluginManifest {
        name: "smoke-decision".to_owned(),
        path: plugin.clone(),
        abi: WasmPluginAbi::FluxheimPolicyV1,
        phases: vec![WasmPluginPhase::RequestHeaders],
        limits,
        fail_mode: WasmPluginFailMode::FailClosed,
    };
    let loaded_manifest_plugin =
        load_plugin_from_manifest(manifest, std::slice::from_ref(&root), false)?;
    if loaded_manifest_plugin.manifest().path() != plugin {
        return Err("validated manifest path drifted".into());
    }

    let unsafe_manifest = WasmPluginManifest {
        name: "unsafe-access".to_owned(),
        path: plugin.clone(),
        abi: WasmPluginAbi::FluxheimPolicyV1,
        phases: vec![WasmPluginPhase::AccessDecision],
        limits,
        fail_mode: WasmPluginFailMode::FailOpen,
    };
    match validate_plugin_manifest(unsafe_manifest, false) {
        Err(WasmManifestError::UnsafeFailOpen) => {}
        Ok(_) => return Err("unsafe fail-open manifest was accepted".into()),
        Err(error) => {
            return Err(format!("expected unsafe fail-open rejection, got {error}").into());
        }
    }

    let runtime = FluxWasmRuntime::new(limits)?;
    let outcome = runtime.run_i32_no_args(loaded_manifest_plugin.file(), "decision")?;
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

    let table_grower = root.join("table-grow.wasm");
    fs::write(
        &table_grower,
        wat::parse_str(
            r#"
            (module
              (table 1 100 funcref)
              (func (export "decision") (result i32)
                ref.null func
                i32.const 20
                table.grow))
            "#,
        )?,
    )?;
    let table_limited = WasmSandboxLimits {
        max_table_elements: 10,
        ..WasmSandboxLimits::default()
    };
    let loaded_table_grower =
        load_plugin_file(&table_grower, std::slice::from_ref(&root), table_limited)?;
    let runtime = FluxWasmRuntime::new(table_limited)?;
    let outcome = runtime.run_i32_no_args(&loaded_table_grower, "decision")?;
    if outcome.result != -1 {
        return Err(format!("expected table growth denial -1, got {}", outcome.result).into());
    }

    fs::remove_dir_all(&root)?;
    Ok(())
}
