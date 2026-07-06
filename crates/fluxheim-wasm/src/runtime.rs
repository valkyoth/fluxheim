use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, OnceLock, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use thiserror::Error;
use wasmtime::{
    Config, Engine, Instance, Linker, Module, Store, StoreLimits, StoreLimitsBuilder,
    UpdateDeadline,
};

use crate::{WasmPluginError, WasmPluginFile, WasmSandboxLimits};

const MAX_CONCURRENT_COMPILES: usize = 16;

#[derive(Debug)]
pub struct FluxWasmRuntime {
    engine: Engine,
    limits: WasmSandboxLimits,
}

#[derive(Debug, Clone)]
pub struct FluxWasmCompiledModule {
    module: Module,
    plugin_sha256: String,
}

#[derive(Clone)]
pub struct WasmI32HostFunction {
    module: &'static str,
    name: &'static str,
    callback: Arc<dyn Fn(i32, i32) -> Result<i32, String> + Send + Sync>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WasmExecutionOutcome {
    pub function: String,
    pub result: i32,
    pub plugin_sha256: String,
}

#[derive(Debug, Clone)]
pub struct FluxWasmAdmissionController {
    active: Arc<AtomicUsize>,
    max_total_concurrent_executions: usize,
}

#[derive(Debug)]
pub struct FluxWasmAdmissionPermit {
    active: Arc<AtomicUsize>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum WasmAdmissionError {
    #[error("wasm admission limit must be greater than zero")]
    InvalidLimit,
    #[error("wasm process-wide execution admission limit reached")]
    GlobalLimitReached,
}

impl Drop for FluxWasmAdmissionPermit {
    fn drop(&mut self) {
        self.active.fetch_sub(1, Ordering::AcqRel);
    }
}

impl FluxWasmAdmissionController {
    pub fn new(max_total_concurrent_executions: usize) -> Result<Self, WasmAdmissionError> {
        if max_total_concurrent_executions == 0 {
            return Err(WasmAdmissionError::InvalidLimit);
        }
        Ok(Self {
            active: Arc::new(AtomicUsize::new(0)),
            max_total_concurrent_executions,
        })
    }

    pub fn active_executions(&self) -> usize {
        self.active.load(Ordering::Acquire)
    }

    pub fn try_acquire(&self) -> Result<FluxWasmAdmissionPermit, WasmAdmissionError> {
        let mut current = self.active.load(Ordering::Acquire);
        loop {
            if current >= self.max_total_concurrent_executions {
                return Err(WasmAdmissionError::GlobalLimitReached);
            }
            match self.active.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(FluxWasmAdmissionPermit {
                        active: Arc::clone(&self.active),
                    });
                }
                Err(observed) => current = observed,
            }
        }
    }
}

impl WasmI32HostFunction {
    pub fn new(
        module: &'static str,
        name: &'static str,
        callback: impl Fn(i32, i32) -> Result<i32, String> + Send + Sync + 'static,
    ) -> Self {
        Self {
            module,
            name,
            callback: Arc::new(callback),
        }
    }
}

#[derive(Debug, Error)]
pub enum WasmExecutionError {
    #[error(transparent)]
    Plugin(#[from] WasmPluginError),
    #[error("wasm runtime setup failed: {0}")]
    RuntimeSetup(String),
    #[error("wasm module compile failed: {0}")]
    Compile(String),
    #[error("wasm module compile concurrency limit reached")]
    CompileConcurrencyLimit,
    #[error("wasm module compile timed out after {timeout_ms}ms")]
    CompileTimeout { timeout_ms: u128 },
    #[error("wasm execution timed out after {timeout_ms}ms")]
    ExecutionTimeout { timeout_ms: u128 },
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

#[derive(Debug)]
struct CounterPermit {
    counter: &'static AtomicUsize,
}

impl Drop for CounterPermit {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

fn compile_slots() -> &'static AtomicUsize {
    static SLOTS: OnceLock<AtomicUsize> = OnceLock::new();
    SLOTS.get_or_init(|| AtomicUsize::new(0))
}

fn acquire_counter_permit(
    counter: &'static AtomicUsize,
    limit: usize,
) -> Result<CounterPermit, WasmExecutionError> {
    let mut current = counter.load(Ordering::Acquire);
    loop {
        if current >= limit {
            return Err(WasmExecutionError::CompileConcurrencyLimit);
        }
        match counter.compare_exchange_weak(
            current,
            current + 1,
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(_) => return Ok(CounterPermit { counter }),
            Err(observed) => current = observed,
        }
    }
}

fn acquire_counter_permit_with_timeout(
    counter: &'static AtomicUsize,
    limit: usize,
    timeout: Duration,
) -> Result<CounterPermit, WasmExecutionError> {
    let started = Instant::now();
    loop {
        match acquire_counter_permit(counter, limit) {
            Ok(permit) => return Ok(permit),
            Err(WasmExecutionError::CompileConcurrencyLimit) if started.elapsed() < timeout => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
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
        let module = self.compile_plugin_module(plugin)?;
        self.run_compiled_i32_no_args(&module, function)
    }

    pub fn compile_plugin_module(
        &self,
        plugin: &WasmPluginFile,
    ) -> Result<FluxWasmCompiledModule, WasmExecutionError> {
        Ok(FluxWasmCompiledModule {
            module: self.compile_module(plugin)?,
            plugin_sha256: plugin.sha256_hex().to_owned(),
        })
    }

    pub fn run_compiled_i32_no_args(
        &self,
        module: &FluxWasmCompiledModule,
        function: &str,
    ) -> Result<WasmExecutionOutcome, WasmExecutionError> {
        self.run_compiled_i32_no_args_with_hosts(module, function, Vec::new())
    }

    pub fn run_compiled_i32_no_args_with_hosts(
        &self,
        module: &FluxWasmCompiledModule,
        function: &str,
        host_functions: Vec<WasmI32HostFunction>,
    ) -> Result<WasmExecutionOutcome, WasmExecutionError> {
        let state = RuntimeStoreState {
            limits: StoreLimitsBuilder::new()
                .memory_size(self.limits.max_memory_bytes)
                .table_elements(self.limits.max_table_elements)
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
        let deadline = Instant::now() + self.limits.timeout;
        store.epoch_deadline_callback(move |_store| {
            if Instant::now() >= deadline {
                Ok(UpdateDeadline::Interrupt)
            } else {
                Ok(UpdateDeadline::Continue(1))
            }
        });

        let timed_out = Arc::new(AtomicBool::new(false));
        let watchdog_timed_out = Arc::clone(&timed_out);
        let (watchdog_cancel, watchdog_cancelled) = mpsc::channel();
        let watchdog_engine = self.engine.clone();
        let timeout = self.limits.timeout;
        let watchdog = thread::spawn(move || {
            if watchdog_cancelled.recv_timeout(timeout).is_err() {
                watchdog_timed_out.store(true, Ordering::Release);
                watchdog_engine.increment_epoch();
            }
        });

        let result = (|| {
            let mut linker = Linker::new(&self.engine);
            let has_host_functions = !host_functions.is_empty();
            for host_function in host_functions {
                let callback = host_function.callback.clone();
                linker
                    .func_wrap(
                        host_function.module,
                        host_function.name,
                        move |left: i32, right: i32| -> wasmtime::Result<i32> {
                            callback(left, right).map_err(wasmtime::Error::msg)
                        },
                    )
                    .map_err(|error| WasmExecutionError::RuntimeSetup(error.to_string()))?;
            }
            let instance = if has_host_functions {
                linker
                    .instantiate(&mut store, &module.module)
                    .map_err(|error| WasmExecutionError::Instantiate(error.to_string()))?
            } else {
                Instance::new(&mut store, &module.module, &[])
                    .map_err(|error| WasmExecutionError::Instantiate(error.to_string()))?
            };
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

        let result = match result {
            Ok(result) => result,
            Err(_) if timed_out.load(Ordering::Acquire) => {
                return Err(WasmExecutionError::ExecutionTimeout {
                    timeout_ms: self.limits.timeout.as_millis(),
                });
            }
            Err(error) => return Err(error),
        };

        Ok(WasmExecutionOutcome {
            function: function.to_owned(),
            result,
            plugin_sha256: module.plugin_sha256.clone(),
        })
    }

    fn compile_module(&self, plugin: &WasmPluginFile) -> Result<Module, WasmExecutionError> {
        self.compile_module_with_counter(plugin, compile_slots(), MAX_CONCURRENT_COMPILES)
    }

    fn compile_module_with_counter(
        &self,
        plugin: &WasmPluginFile,
        counter: &'static AtomicUsize,
        limit: usize,
    ) -> Result<Module, WasmExecutionError> {
        let started = Instant::now();
        let compile_permit =
            acquire_counter_permit_with_timeout(counter, limit, self.limits.compile_timeout)?;
        let remaining_timeout = self
            .limits
            .compile_timeout
            .checked_sub(started.elapsed())
            .unwrap_or(Duration::ZERO);
        let engine = self.engine.clone();
        let bytes = plugin.bytes().to_vec();
        let (result_sender, result_receiver) = mpsc::sync_channel(1);
        thread::spawn(move || {
            let result = Module::new(&engine, &bytes)
                .map_err(|error| WasmExecutionError::Compile(error.to_string()));
            drop(compile_permit);
            let _ = result_sender.send(result);
        });

        match result_receiver.recv_timeout(remaining_timeout) {
            Ok(result) => result,
            Err(mpsc::RecvTimeoutError::Timeout) => Err(WasmExecutionError::CompileTimeout {
                timeout_ms: self.limits.compile_timeout.as_millis(),
            }),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(WasmExecutionError::Compile(
                "compile worker failed".to_owned(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::sync::mpsc;
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
    fn compiled_module_execution_does_not_need_compile_slots() {
        let counter = Box::leak(Box::new(AtomicUsize::new(0)));
        let directory = tempfile::tempdir().unwrap();
        let plugin_path = write_wat_plugin(
            &directory,
            r#"(module (func (export "decision") (result i32) i32.const 7))"#,
        );
        let limits = WasmSandboxLimits::default();
        let plugin =
            load_plugin_file(&plugin_path, &[directory.path().to_path_buf()], limits).unwrap();
        let runtime = FluxWasmRuntime::new(limits).unwrap();
        let module = FluxWasmCompiledModule {
            module: runtime
                .compile_module_with_counter(&plugin, counter, 1)
                .unwrap(),
            plugin_sha256: plugin.sha256_hex().to_owned(),
        };
        let permit = acquire_counter_permit(counter, 1).unwrap();

        let outcome = runtime
            .run_compiled_i32_no_args(&module, "decision")
            .unwrap();
        let error = runtime
            .compile_module_with_counter(&plugin, counter, 1)
            .unwrap_err();

        assert_eq!(outcome.result, 7);
        assert!(matches!(error, WasmExecutionError::CompileConcurrencyLimit));
        drop(permit);
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
    fn runtime_reports_wall_time_timeout_separately_from_traps() {
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
            fuel: 1_000_000_000,
            timeout: Duration::from_millis(25),
            ..WasmSandboxLimits::default()
        };
        let plugin =
            load_plugin_file(&plugin_path, &[directory.path().to_path_buf()], limits).unwrap();
        let runtime = FluxWasmRuntime::new(limits).unwrap();

        let error = runtime.run_i32_no_args(&plugin, "spin").unwrap_err();

        assert!(matches!(error, WasmExecutionError::ExecutionTimeout { .. }));
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

    #[test]
    fn runtime_rejects_excessive_table_declaration() {
        let directory = tempfile::tempdir().unwrap();
        let plugin_path = write_wat_plugin(
            &directory,
            r#"
            (module
              (table 11 funcref)
              (func (export "decision") (result i32) i32.const 1))
            "#,
        );
        let limits = WasmSandboxLimits {
            max_table_elements: 10,
            ..WasmSandboxLimits::default()
        };
        let plugin =
            load_plugin_file(&plugin_path, &[directory.path().to_path_buf()], limits).unwrap();
        let runtime = FluxWasmRuntime::new(limits).unwrap();

        let error = runtime.run_i32_no_args(&plugin, "decision").unwrap_err();

        assert!(matches!(error, WasmExecutionError::Instantiate(_)));
    }

    #[test]
    fn runtime_denies_table_growth_beyond_limit() {
        let directory = tempfile::tempdir().unwrap();
        let plugin_path = write_wat_plugin(
            &directory,
            r#"
            (module
              (table 1 100 funcref)
              (func (export "decision") (result i32)
                ref.null func
                i32.const 20
                table.grow))
            "#,
        );
        let limits = WasmSandboxLimits {
            max_table_elements: 10,
            ..WasmSandboxLimits::default()
        };
        let plugin =
            load_plugin_file(&plugin_path, &[directory.path().to_path_buf()], limits).unwrap();
        let runtime = FluxWasmRuntime::new(limits).unwrap();

        let outcome = runtime.run_i32_no_args(&plugin, "decision").unwrap();

        assert_eq!(outcome.result, -1);
    }

    #[test]
    fn compile_counter_rejects_calls_above_limit_until_permit_drops() {
        let counter = Box::leak(Box::new(AtomicUsize::new(0)));
        let first = acquire_counter_permit(counter, 2).unwrap();
        let second = acquire_counter_permit(counter, 2).unwrap();

        let error = acquire_counter_permit(counter, 2).unwrap_err();

        assert!(matches!(error, WasmExecutionError::CompileConcurrencyLimit));
        drop(first);
        let third = acquire_counter_permit(counter, 2).unwrap();
        assert_eq!(counter.load(Ordering::Acquire), 2);
        drop(second);
        drop(third);
        assert_eq!(counter.load(Ordering::Acquire), 0);
    }

    #[test]
    fn runtime_ignores_external_epoch_ticks_before_own_deadline() {
        let directory = tempfile::tempdir().unwrap();
        let plugin_path = write_wat_plugin(
            &directory,
            r#"
            (module
              (func (export "decision") (result i32)
                (local $i i32)
                (loop $again
                  local.get $i
                  i32.const 1
                  i32.add
                  local.tee $i
                  i32.const 200000
                  i32.lt_s
                  br_if $again)
                i32.const 9))
            "#,
        );
        let limits = WasmSandboxLimits {
            fuel: 5_000_000,
            timeout: Duration::from_secs(5),
            ..WasmSandboxLimits::default()
        };
        let plugin =
            load_plugin_file(&plugin_path, &[directory.path().to_path_buf()], limits).unwrap();
        let runtime = FluxWasmRuntime::new(limits).unwrap();
        let engine = runtime.engine.clone();
        let (stop_sender, stop_receiver) = mpsc::channel();
        let ticker = thread::spawn(move || {
            loop {
                match stop_receiver.try_recv() {
                    Ok(()) | Err(mpsc::TryRecvError::Disconnected) => break,
                    Err(mpsc::TryRecvError::Empty) => {
                        engine.increment_epoch();
                        thread::yield_now();
                    }
                }
            }
        });

        let result = runtime.run_i32_no_args(&plugin, "decision");

        let _ = stop_sender.send(());
        let _ = ticker.join();
        let outcome = result.unwrap();
        assert_eq!(outcome.result, 9);
    }

    #[test]
    fn admission_controller_enforces_process_wide_limit_until_permit_drops() {
        let controller = FluxWasmAdmissionController::new(2).unwrap();
        let first = controller.try_acquire().unwrap();
        let second = controller.try_acquire().unwrap();

        let error = controller.try_acquire().unwrap_err();

        assert_eq!(error, WasmAdmissionError::GlobalLimitReached);
        assert_eq!(controller.active_executions(), 2);
        drop(first);
        let third = controller.try_acquire().unwrap();
        assert_eq!(controller.active_executions(), 2);
        drop(second);
        drop(third);
        assert_eq!(controller.active_executions(), 0);
    }

    #[test]
    fn admission_controller_rejects_zero_limit() {
        let error = FluxWasmAdmissionController::new(0).unwrap_err();

        assert_eq!(error, WasmAdmissionError::InvalidLimit);
    }
}
