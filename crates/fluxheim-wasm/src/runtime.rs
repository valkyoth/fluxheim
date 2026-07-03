use std::sync::mpsc;
use std::thread;

use thiserror::Error;
use wasmtime::{Config, Engine, Instance, Module, Store, StoreLimits, StoreLimitsBuilder};

use crate::{WasmPluginError, WasmPluginFile, WasmSandboxLimits};

#[derive(Debug)]
pub struct FluxWasmRuntime {
    engine: Engine,
    limits: WasmSandboxLimits,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WasmExecutionOutcome {
    pub function: String,
    pub result: i32,
    pub plugin_sha256: String,
}

#[derive(Debug, Error)]
pub enum WasmExecutionError {
    #[error(transparent)]
    Plugin(#[from] WasmPluginError),
    #[error("wasm runtime setup failed: {0}")]
    RuntimeSetup(String),
    #[error("wasm module compile failed: {0}")]
    Compile(String),
    #[error("wasm module instantiation failed: {0}")]
    Instantiate(String),
    #[error("wasm exported function {function:?} is missing or has the wrong type: {message}")]
    FunctionType { function: String, message: String },
    #[error("wasm execution trapped or exceeded limits: {0}")]
    Trap(String),
}

struct RuntimeStoreState {
    limits: StoreLimits,
}

impl FluxWasmRuntime {
    pub fn new(limits: WasmSandboxLimits) -> Result<Self, WasmExecutionError> {
        let limits = limits.validate()?;
        let mut config = Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);
        let engine = Engine::new(&config)
            .map_err(|error| WasmExecutionError::RuntimeSetup(error.to_string()))?;
        Ok(Self { engine, limits })
    }

    pub fn run_i32_no_args(
        &self,
        plugin: &WasmPluginFile,
        function: &str,
    ) -> Result<WasmExecutionOutcome, WasmExecutionError> {
        let module = Module::new(&self.engine, plugin.bytes())
            .map_err(|error| WasmExecutionError::Compile(error.to_string()))?;
        let state = RuntimeStoreState {
            limits: StoreLimitsBuilder::new()
                .memory_size(self.limits.max_memory_bytes)
                .instances(1)
                .memories(1)
                .tables(2)
                .build(),
        };
        let mut store = Store::new(&self.engine, state);
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(self.limits.fuel)
            .map_err(|error| WasmExecutionError::RuntimeSetup(error.to_string()))?;
        store.set_epoch_deadline(1);
        store.epoch_deadline_trap();

        let (watchdog_cancel, watchdog_cancelled) = mpsc::channel();
        let watchdog_engine = self.engine.clone();
        let timeout = self.limits.timeout;
        let watchdog = thread::spawn(move || {
            if watchdog_cancelled.recv_timeout(timeout).is_err() {
                watchdog_engine.increment_epoch();
            }
        });

        let result = (|| {
            let instance = Instance::new(&mut store, &module, &[])
                .map_err(|error| WasmExecutionError::Instantiate(error.to_string()))?;
            let exported = instance
                .get_typed_func::<(), i32>(&mut store, function)
                .map_err(|error| WasmExecutionError::FunctionType {
                    function: function.to_owned(),
                    message: error.to_string(),
                })?;
            exported
                .call(&mut store, ())
                .map_err(|error| WasmExecutionError::Trap(error.to_string()))
        })();

        let _ = watchdog_cancel.send(());
        let _ = watchdog.join();

        Ok(WasmExecutionOutcome {
            function: function.to_owned(),
            result: result?,
            plugin_sha256: plugin.sha256_hex().to_owned(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::Duration;

    use crate::load_plugin_file;

    fn write_wat_plugin(directory: &tempfile::TempDir, source: &str) -> std::path::PathBuf {
        let bytes = wat::parse_str(source).unwrap();
        let path = directory.path().join("plugin.wasm");
        fs::write(&path, bytes).unwrap();
        path
    }

    #[test]
    fn runtime_executes_real_wasm_function() {
        let directory = tempfile::tempdir().unwrap();
        let plugin_path = write_wat_plugin(
            &directory,
            r#"(module (func (export "decision") (result i32) i32.const 7))"#,
        );
        let limits = WasmSandboxLimits::default();
        let plugin =
            load_plugin_file(&plugin_path, &[directory.path().to_path_buf()], limits).unwrap();
        let runtime = FluxWasmRuntime::new(limits).unwrap();

        let outcome = runtime.run_i32_no_args(&plugin, "decision").unwrap();

        assert_eq!(outcome.function, "decision");
        assert_eq!(outcome.result, 7);
        assert_eq!(outcome.plugin_sha256.len(), 64);
    }

    #[test]
    fn runtime_traps_when_fuel_is_exhausted() {
        let directory = tempfile::tempdir().unwrap();
        let plugin_path = write_wat_plugin(
            &directory,
            r#"
            (module
              (func (export "spin") (result i32)
                (loop br 0)
                i32.const 0))
            "#,
        );
        let limits = WasmSandboxLimits {
            fuel: 1_000,
            timeout: Duration::from_secs(1),
            ..WasmSandboxLimits::default()
        };
        let plugin =
            load_plugin_file(&plugin_path, &[directory.path().to_path_buf()], limits).unwrap();
        let runtime = FluxWasmRuntime::new(limits).unwrap();

        let error = runtime.run_i32_no_args(&plugin, "spin").unwrap_err();

        assert!(matches!(error, WasmExecutionError::Trap(_)));
    }

    #[test]
    fn runtime_rejects_excessive_memory_declaration() {
        let directory = tempfile::tempdir().unwrap();
        let plugin_path = write_wat_plugin(
            &directory,
            r#"
            (module
              (memory 2)
              (func (export "decision") (result i32) i32.const 1))
            "#,
        );
        let limits = WasmSandboxLimits {
            max_memory_bytes: 64 * 1024,
            ..WasmSandboxLimits::default()
        };
        let plugin =
            load_plugin_file(&plugin_path, &[directory.path().to_path_buf()], limits).unwrap();
        let runtime = FluxWasmRuntime::new(limits).unwrap();

        let error = runtime.run_i32_no_args(&plugin, "decision").unwrap_err();

        assert!(matches!(error, WasmExecutionError::Instantiate(_)));
    }
}
