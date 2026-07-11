use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Duration;

#[cfg(feature = "wasi")]
use fluxheim_wasm::WasmWasiCapabilities;
use fluxheim_wasm::{
    FluxWasmRuntime, WasmExecutionError, WasmHostCallNamespace, WasmManifestError, WasmPluginAbi,
    WasmPluginFailMode, WasmPluginManifest, WasmPluginPhase, WasmSandboxLimits, load_plugin_file,
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
    let directory = tempfile::Builder::new()
        .prefix("fluxheim-wasm-smoke-")
        .tempdir()?;
    let root = directory.path().to_path_buf();
    let plugin = write_wasm_fixture(
        &root,
        "decision-",
        r#"(module (func (export "decision") (result i32) i32.const 42))"#,
    )?;

    let limits = WasmSandboxLimits {
        fuel: 50_000,
        timeout: Duration::from_millis(100),
        ..WasmSandboxLimits::default()
    };
    let manifest = WasmPluginManifest {
        name: "smoke-decision".to_owned(),
        path: plugin.clone(),
        expected_sha256: None,
        abi: WasmPluginAbi::FluxheimPolicyV1,
        host_call_namespace: WasmHostCallNamespace::FluxheimPolicyV1,
        wasi_capabilities: Default::default(),
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
        expected_sha256: None,
        abi: WasmPluginAbi::FluxheimPolicyV1,
        host_call_namespace: WasmHostCallNamespace::FluxheimPolicyV1,
        wasi_capabilities: Default::default(),
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

    let spinner = write_wasm_fixture(
        &root,
        "spin-",
        r#"
            (module
              (func (export "spin") (result i32)
                (loop br 0)
                i32.const 0))
            "#,
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

    let table_grower = write_wasm_fixture(
        &root,
        "table-grow-",
        r#"
            (module
              (table 1 100 funcref)
              (func (export "decision") (result i32)
                ref.null func
                i32.const 20
                table.grow))
            "#,
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

    #[cfg(feature = "wasi")]
    run_wasi_preview(&root, limits)?;

    Ok(())
}

#[cfg(feature = "wasi")]
fn run_wasi_preview(
    root: &Path,
    limits: WasmSandboxLimits,
) -> Result<(), Box<dyn std::error::Error>> {
    let approved_roots = [root.to_path_buf()];
    let plugin = write_wasm_fixture(
        root,
        "wasi-random-",
        include_str!("../../../examples/wasm/wasi-random-policy.wat"),
    )?;
    let manifest = WasmPluginManifest {
        name: "wasi-random".to_owned(),
        path: plugin.clone(),
        expected_sha256: None,
        abi: WasmPluginAbi::WasiPreview,
        host_call_namespace: WasmHostCallNamespace::WasiPreview,
        wasi_capabilities: WasmWasiCapabilities {
            randomness: true,
            ..WasmWasiCapabilities::default()
        },
        phases: vec![WasmPluginPhase::AccessDecision],
        limits,
        fail_mode: WasmPluginFailMode::FailClosed,
    };
    let loaded = load_plugin_from_manifest(manifest, &approved_roots, true)?;
    let runtime = FluxWasmRuntime::new(limits)?;
    let identity = fluxheim_wasm::FluxWasmCompiledModuleIdentity::for_loaded_plugin(
        &loaded,
        "smoke:wasi-preview:randomness",
    );
    let compiled = runtime.compile_plugin_module_with_identity(loaded.file(), identity)?;
    let outcome = runtime.run_compiled_i32_no_args(&compiled, "fluxheim_access_decision")?;
    if outcome.result != 0 {
        return Err(format!("expected WASI random_get success, got {}", outcome.result).into());
    }

    let denied_manifest = WasmPluginManifest {
        name: "wasi-random-denied".to_owned(),
        path: plugin,
        expected_sha256: None,
        abi: WasmPluginAbi::WasiPreview,
        host_call_namespace: WasmHostCallNamespace::WasiPreview,
        wasi_capabilities: WasmWasiCapabilities::default(),
        phases: vec![WasmPluginPhase::AccessDecision],
        limits,
        fail_mode: WasmPluginFailMode::FailClosed,
    };
    let denied = load_plugin_from_manifest(denied_manifest, &approved_roots, true)?;
    let identity = fluxheim_wasm::FluxWasmCompiledModuleIdentity::for_loaded_plugin(
        &denied,
        "smoke:wasi-preview:denied",
    );
    let compiled = runtime.compile_plugin_module_with_identity(denied.file(), identity)?;
    match runtime.run_compiled_i32_no_args(&compiled, "fluxheim_access_decision") {
        Err(WasmExecutionError::UnsupportedHostImport { module, name })
            if module == "wasi_snapshot_preview1" && name == "random_get" => {}
        Ok(_) => return Err("ungranted WASI randomness import unexpectedly executed".into()),
        Err(error) => {
            return Err(format!("expected ungranted WASI import rejection, got {error}").into());
        }
    }
    Ok(())
}

fn write_wasm_fixture(
    root: &Path,
    prefix: &str,
    wat_source: &str,
) -> Result<PathBuf, Box<dyn std::error::Error>> {
    let mut file = tempfile::Builder::new()
        .prefix(prefix)
        .suffix(".wasm")
        .tempfile_in(root)?;
    file.write_all(&wat::parse_str(wat_source)?)?;
    let (_file, path) = file.keep()?;
    Ok(path)
}
