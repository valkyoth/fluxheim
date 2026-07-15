#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use thiserror::Error;
use wasmtime::{
    Config, Engine, Instance, Linker, Module, Store, StoreLimits, StoreLimitsBuilder,
    UpdateDeadline,
};
#[cfg(feature = "wasi")]
use wasmtime_wasi::{WasiCtxBuilder, p1::WasiP1Ctx};

use crate::{
    FLUXHEIM_WASM_ABI_VERSION, LoadedWasmPlugin, WasmPluginError, WasmPluginFile,
    WasmSandboxLimits, WasmWasiCapabilities,
};

const MAX_CONCURRENT_COMPILES: usize = 2;
const DEFAULT_RUNTIME_FEATURE_SET: &str = "fluxheim-policy-v1";
const EPOCH_TICK_INTERVAL: Duration = Duration::from_millis(1);
#[cfg(feature = "wasi")]
const MAX_WASI_RANDOM_BYTES_PER_CALL: u64 = 4096;

#[derive(Debug)]
pub struct FluxWasmRuntime {
    engine: Engine,
    limits: WasmSandboxLimits,
}

#[derive(Debug, Clone)]
pub struct FluxWasmCompiledModule {
    module: Module,
    cache_identity: FluxWasmCompiledModuleIdentity,
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct FluxWasmCompiledModuleIdentity {
    plugin_sha256: String,
    abi_version: u32,
    fluxheim_version: String,
    feature_set: String,
    wasi_capabilities: WasmWasiCapabilities,
}

#[derive(Clone)]
/// Synchronous native host callback for Fluxheim's bounded policy ABI.
///
/// Callbacks must be finite, non-blocking, panic-free, and total over every
/// possible `i32` input. They must use checked arithmetic and bounds-checked
/// access and remain free of I/O, sleeps, IPC, assertion-based APIs, and
/// contended lock acquisition. Wasmtime epoch interruption cannot preempt
/// native Rust while a callback is running, and Fluxheim releases abort on
/// panic rather than unwind.
pub struct WasmI32HostFunction {
    module: &'static str,
    name: &'static str,
    callback: WasmI32HostCallback,
}

type WasmI32HostCallback2 = dyn Fn(i32, i32) -> Result<i32, String> + Send + Sync;
type WasmI32HostCallback3 = dyn Fn(i32, i32, i32) -> Result<i32, String> + Send + Sync;

#[derive(Clone)]
enum WasmI32HostCallback {
    Two(Arc<WasmI32HostCallback2>),
    Three(Arc<WasmI32HostCallback3>),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WasmExecutionOutcome {
    pub function: String,
    pub result: i32,
    pub plugin_sha256: String,
}

#[derive(Debug, Clone)]
pub struct FluxWasmAdmissionController {
    active: Arc<Semaphore>,
    total: Arc<Semaphore>,
    max_total_concurrent_executions: usize,
    total_capacity: usize,
    queue_limit: usize,
}

#[derive(Debug)]
pub struct FluxWasmAdmissionPermit {
    _active: OwnedSemaphorePermit,
    _total: OwnedSemaphorePermit,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum WasmAdmissionError {
    #[error("wasm admission limit must be greater than zero")]
    InvalidLimit,
    #[error("wasm process-wide execution admission limit reached")]
    GlobalLimitReached,
    #[error("wasm execution admission queue is full")]
    QueueFull,
}

impl FluxWasmAdmissionController {
    pub fn new(max_total_concurrent_executions: usize) -> Result<Self, WasmAdmissionError> {
        Self::new_with_queue(max_total_concurrent_executions, 0)
    }

    pub fn new_with_queue(
        max_total_concurrent_executions: usize,
        queue_limit: usize,
    ) -> Result<Self, WasmAdmissionError> {
        if max_total_concurrent_executions == 0
            || max_total_concurrent_executions > Semaphore::MAX_PERMITS
        {
            return Err(WasmAdmissionError::InvalidLimit);
        }
        let total_capacity = max_total_concurrent_executions
            .checked_add(queue_limit)
            .filter(|total| *total <= Semaphore::MAX_PERMITS)
            .ok_or(WasmAdmissionError::InvalidLimit)?;
        Ok(Self {
            active: Arc::new(Semaphore::new(max_total_concurrent_executions)),
            total: Arc::new(Semaphore::new(total_capacity)),
            max_total_concurrent_executions,
            total_capacity,
            queue_limit,
        })
    }

    pub fn active_executions(&self) -> usize {
        self.max_total_concurrent_executions
            .saturating_sub(self.active.available_permits())
    }

    pub fn queued_executions(&self) -> usize {
        self.total_capacity
            .saturating_sub(self.total.available_permits())
            .saturating_sub(self.active_executions())
    }

    pub fn try_acquire(&self) -> Result<FluxWasmAdmissionPermit, WasmAdmissionError> {
        let total = self.total.clone().try_acquire_owned().map_err(|_| {
            if self.queue_limit == 0 {
                WasmAdmissionError::GlobalLimitReached
            } else {
                WasmAdmissionError::QueueFull
            }
        })?;
        let active = self
            .active
            .clone()
            .try_acquire_owned()
            .map_err(|_| WasmAdmissionError::GlobalLimitReached)?;
        Ok(FluxWasmAdmissionPermit {
            _active: active,
            _total: total,
        })
    }

    pub async fn acquire(&self) -> Result<FluxWasmAdmissionPermit, WasmAdmissionError> {
        let total = self.total.clone().try_acquire_owned().map_err(|_| {
            if self.queue_limit == 0 {
                WasmAdmissionError::GlobalLimitReached
            } else {
                WasmAdmissionError::QueueFull
            }
        })?;
        let active = self
            .active
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| WasmAdmissionError::GlobalLimitReached)?;
        Ok(FluxWasmAdmissionPermit {
            _active: active,
            _total: total,
        })
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
            callback: WasmI32HostCallback::Two(Arc::new(callback)),
        }
    }

    pub fn new_i32x3(
        module: &'static str,
        name: &'static str,
        callback: impl Fn(i32, i32, i32) -> Result<i32, String> + Send + Sync + 'static,
    ) -> Self {
        Self {
            module,
            name,
            callback: WasmI32HostCallback::Three(Arc::new(callback)),
        }
    }
}

impl FluxWasmCompiledModule {
    pub fn cache_identity(&self) -> &FluxWasmCompiledModuleIdentity {
        &self.cache_identity
    }

    pub fn plugin_sha256(&self) -> &str {
        self.cache_identity.plugin_sha256()
    }
}

impl FluxWasmCompiledModuleIdentity {
    pub fn new(
        plugin_sha256: impl Into<String>,
        abi_version: u32,
        feature_set: impl Into<String>,
    ) -> Self {
        Self {
            plugin_sha256: plugin_sha256.into().to_ascii_lowercase(),
            abi_version,
            fluxheim_version: env!("CARGO_PKG_VERSION").to_owned(),
            feature_set: feature_set.into(),
            wasi_capabilities: WasmWasiCapabilities::default(),
        }
    }

    pub fn for_loaded_plugin(plugin: &LoadedWasmPlugin, feature_set: impl Into<String>) -> Self {
        let mut identity = Self::new(
            plugin.file().sha256_hex(),
            plugin.manifest().abi().abi_version(),
            feature_set,
        );
        identity.wasi_capabilities = plugin.manifest().wasi_capabilities();
        identity
    }

    pub fn plugin_sha256(&self) -> &str {
        &self.plugin_sha256
    }

    pub fn abi_version(&self) -> u32 {
        self.abi_version
    }

    pub fn fluxheim_version(&self) -> &str {
        &self.fluxheim_version
    }

    pub fn feature_set(&self) -> &str {
        &self.feature_set
    }

    pub fn wasi_capabilities(&self) -> WasmWasiCapabilities {
        self.wasi_capabilities
    }

    pub fn with_wasi_capabilities(mut self, capabilities: WasmWasiCapabilities) -> Self {
        self.wasi_capabilities = capabilities;
        self
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
    #[error("wasm compiled artifact is too large: max {max_bytes} bytes")]
    CompiledArtifactOversized { max_bytes: usize },
    #[error("wasm execution timed out after {timeout_ms}ms")]
    ExecutionTimeout { timeout_ms: u128 },
    #[error("wasm module instantiation failed: {0}")]
    Instantiate(String),
    #[error("wasm host import {module}.{name} is not available in the selected namespace")]
    UnsupportedHostImport { module: String, name: String },
    #[error("wasm exported function {function:?} is missing or has the wrong type: {message}")]
    FunctionType { function: String, message: String },
    #[error("wasm execution trapped or exceeded limits: {0}")]
    Trap(String),
}

struct RuntimeStoreState {
    limits: StoreLimits,
    #[cfg(feature = "wasi")]
    wasi: WasiP1Ctx,
}

#[cfg(test)]
#[derive(Debug)]
struct CounterPermit {
    counter: &'static AtomicUsize,
}

struct CompileSlotPool {
    active: Mutex<usize>,
    available: Condvar,
}

struct CompileSlotPermit {
    pool: &'static CompileSlotPool,
}

#[cfg(test)]
impl Drop for CounterPermit {
    fn drop(&mut self) {
        self.counter.fetch_sub(1, Ordering::AcqRel);
    }
}

impl Drop for CompileSlotPermit {
    fn drop(&mut self) {
        let mut active = self.pool.active.lock().unwrap_or_else(|poisoned| {
            let _ = poisoned;
            std::process::abort();
        });
        *active = active.saturating_sub(1);
        self.pool.available.notify_one();
    }
}

fn compile_slot_pool() -> &'static CompileSlotPool {
    static POOL: OnceLock<CompileSlotPool> = OnceLock::new();
    POOL.get_or_init(|| CompileSlotPool {
        active: Mutex::new(0),
        available: Condvar::new(),
    })
}

fn shared_wasm_engine() -> Result<Engine, WasmExecutionError> {
    static ENGINE: OnceLock<Result<Engine, String>> = OnceLock::new();
    match ENGINE.get_or_init(|| {
        let mut config = Config::new();
        config.consume_fuel(true);
        config.epoch_interruption(true);
        Engine::new(&config).map_err(|error| error.to_string())
    }) {
        Ok(engine) => Ok(engine.clone()),
        Err(error) => Err(WasmExecutionError::RuntimeSetup(error.clone())),
    }
}

fn ensure_shared_epoch_ticker(engine: &Engine) -> Result<(), WasmExecutionError> {
    static TICKER: OnceLock<Result<(), String>> = OnceLock::new();
    match TICKER.get_or_init(|| {
        let engine = engine.clone();
        thread::Builder::new()
            .name("fluxheim-wasm-epoch".to_owned())
            .spawn(move || {
                loop {
                    thread::sleep(EPOCH_TICK_INTERVAL);
                    engine.increment_epoch();
                }
            })
            .map(|_| ())
            .map_err(|error| error.to_string())
    }) {
        Ok(()) => Ok(()),
        Err(error) => Err(WasmExecutionError::RuntimeSetup(error.clone())),
    }
}

fn wasi_import_allowed(module: &str, name: &str, capabilities: WasmWasiCapabilities) -> bool {
    if module != "wasi_snapshot_preview1" {
        return false;
    }
    #[cfg(feature = "wasi")]
    {
        match name {
            "clock_res_get" | "clock_time_get" => capabilities.clocks,
            "random_get" => capabilities.randomness,
            _ => false,
        }
    }
    #[cfg(not(feature = "wasi"))]
    {
        let _ = (name, capabilities);
        false
    }
}

#[cfg(test)]
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
    pool: &'static CompileSlotPool,
    limit: usize,
    timeout: Duration,
) -> Result<CompileSlotPermit, WasmExecutionError> {
    let started = Instant::now();
    let mut active = pool.active.lock().unwrap_or_else(|poisoned| {
        let _ = poisoned;
        std::process::abort();
    });
    loop {
        if *active < limit {
            *active += 1;
            return Ok(CompileSlotPermit { pool });
        }
        let Some(remaining) = timeout.checked_sub(started.elapsed()) else {
            return Err(WasmExecutionError::CompileConcurrencyLimit);
        };
        if remaining.is_zero() {
            return Err(WasmExecutionError::CompileConcurrencyLimit);
        }
        let (next_active, wait) = pool
            .available
            .wait_timeout(active, remaining)
            .unwrap_or_else(|_| {
                std::process::abort();
            });
        active = next_active;
        if wait.timed_out() && *active >= limit {
            return Err(WasmExecutionError::CompileConcurrencyLimit);
        }
    }
}

impl FluxWasmRuntime {
    pub fn new(limits: WasmSandboxLimits) -> Result<Self, WasmExecutionError> {
        let limits = limits.validate()?;
        let engine = shared_wasm_engine()?;
        ensure_shared_epoch_ticker(&engine)?;
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
        self.compile_plugin_module_with_identity(
            plugin,
            FluxWasmCompiledModuleIdentity::new(
                plugin.sha256_hex(),
                FLUXHEIM_WASM_ABI_VERSION,
                DEFAULT_RUNTIME_FEATURE_SET,
            ),
        )
    }

    pub fn compile_plugin_module_with_identity(
        &self,
        plugin: &WasmPluginFile,
        cache_identity: FluxWasmCompiledModuleIdentity,
    ) -> Result<FluxWasmCompiledModule, WasmExecutionError> {
        if !cache_identity
            .plugin_sha256()
            .eq_ignore_ascii_case(plugin.sha256_hex())
        {
            return Err(WasmExecutionError::RuntimeSetup(
                "wasm compiled-module identity digest mismatch".to_owned(),
            ));
        }
        Ok(FluxWasmCompiledModule {
            module: self.compile_module(plugin)?,
            cache_identity,
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
        let wasi_capabilities = module.cache_identity.wasi_capabilities();
        if let Some(import) = module.module.imports().find(|import| {
            if import.module() == "wasi_snapshot_preview1" {
                return !wasi_import_allowed(import.module(), import.name(), wasi_capabilities);
            }
            let custom_host_available = host_functions.iter().any(|host_function| {
                host_function.module == import.module() && host_function.name == import.name()
            });
            !custom_host_available
        }) {
            return Err(WasmExecutionError::UnsupportedHostImport {
                module: import.module().to_owned(),
                name: import.name().to_owned(),
            });
        }
        let state = RuntimeStoreState {
            limits: StoreLimitsBuilder::new()
                .memory_size(self.limits.max_memory_bytes)
                .table_elements(self.limits.max_table_elements)
                .instances(1)
                .memories(1)
                .tables(2)
                .build(),
            #[cfg(feature = "wasi")]
            wasi: WasiCtxBuilder::new()
                .max_random_size(MAX_WASI_RANDOM_BYTES_PER_CALL)
                .build_p1(),
        };
        let mut store = Store::new(&self.engine, state);
        store.limiter(|state| &mut state.limits);
        store
            .set_fuel(self.limits.fuel)
            .map_err(|error| WasmExecutionError::RuntimeSetup(error.to_string()))?;
        store.set_epoch_deadline(1);
        let deadline = checked_execution_deadline(Instant::now(), self.limits.timeout)?;
        let timed_out = Arc::new(AtomicBool::new(false));
        let callback_timed_out = Arc::clone(&timed_out);
        store.epoch_deadline_callback(move |_store| {
            if Instant::now() >= deadline {
                callback_timed_out.store(true, Ordering::Release);
                Ok(UpdateDeadline::Interrupt)
            } else {
                Ok(UpdateDeadline::Continue(1))
            }
        });
        let result = (|| {
            let mut linker: Linker<RuntimeStoreState> = Linker::new(&self.engine);
            let has_wasi_imports = module
                .module
                .imports()
                .any(|import| import.module() == "wasi_snapshot_preview1");
            #[cfg(feature = "wasi")]
            if has_wasi_imports {
                wasmtime_wasi::p1::add_to_linker_sync(&mut linker, |state| &mut state.wasi)
                    .map_err(|error| WasmExecutionError::RuntimeSetup(error.to_string()))?;
            }
            let has_host_functions = !host_functions.is_empty() || has_wasi_imports;
            for host_function in host_functions {
                match host_function.callback {
                    WasmI32HostCallback::Two(callback) => {
                        let host_timed_out = Arc::clone(&timed_out);
                        linker
                            .func_wrap(
                                host_function.module,
                                host_function.name,
                                move |left: i32, right: i32| -> wasmtime::Result<i32> {
                                    invoke_bounded_host_callback(deadline, &host_timed_out, || {
                                        callback(left, right)
                                    })
                                    .map_err(wasmtime::Error::msg)
                                },
                            )
                            .map_err(|error| WasmExecutionError::RuntimeSetup(error.to_string()))?
                    }
                    WasmI32HostCallback::Three(callback) => {
                        let host_timed_out = Arc::clone(&timed_out);
                        linker
                            .func_wrap(
                                host_function.module,
                                host_function.name,
                                move |first: i32,
                                      second: i32,
                                      third: i32|
                                      -> wasmtime::Result<i32> {
                                    invoke_bounded_host_callback(deadline, &host_timed_out, || {
                                        callback(first, second, third)
                                    })
                                    .map_err(wasmtime::Error::msg)
                                },
                            )
                            .map_err(|error| WasmExecutionError::RuntimeSetup(error.to_string()))?
                    }
                };
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
            plugin_sha256: module.cache_identity.plugin_sha256.clone(),
        })
    }

    fn compile_module(&self, plugin: &WasmPluginFile) -> Result<Module, WasmExecutionError> {
        self.compile_module_with_slot_pool(plugin, compile_slot_pool(), MAX_CONCURRENT_COMPILES)
    }

    fn compile_module_with_slot_pool(
        &self,
        plugin: &WasmPluginFile,
        pool: &'static CompileSlotPool,
        limit: usize,
    ) -> Result<Module, WasmExecutionError> {
        let started = Instant::now();
        let compile_permit =
            acquire_counter_permit_with_timeout(pool, limit, self.limits.compile_timeout)?;
        let remaining_timeout = self
            .limits
            .compile_timeout
            .checked_sub(started.elapsed())
            .unwrap_or(Duration::ZERO);
        self.compile_module_with_permit(plugin, compile_permit, remaining_timeout)
    }

    #[cfg(test)]
    fn compile_module_with_counter(
        &self,
        plugin: &WasmPluginFile,
        counter: &'static AtomicUsize,
        limit: usize,
    ) -> Result<Module, WasmExecutionError> {
        let compile_permit = acquire_counter_permit(counter, limit)?;
        self.compile_module_with_permit(plugin, compile_permit, self.limits.compile_timeout)
    }

    fn compile_module_with_permit<P>(
        &self,
        plugin: &WasmPluginFile,
        compile_permit: P,
        timeout: Duration,
    ) -> Result<Module, WasmExecutionError> {
        if timeout.is_zero() {
            return Err(WasmExecutionError::CompileTimeout {
                timeout_ms: self.limits.compile_timeout.as_millis(),
            });
        }

        let started = Instant::now();
        let result = Module::new(&self.engine, plugin.bytes())
            .map_err(|error| WasmExecutionError::Compile(error.to_string()))
            .and_then(|module| {
                let artifact = module
                    .serialize()
                    .map_err(|error| WasmExecutionError::Compile(error.to_string()))?;
                if artifact.len() > self.limits.max_compiled_artifact_bytes {
                    return Err(WasmExecutionError::CompiledArtifactOversized {
                        max_bytes: self.limits.max_compiled_artifact_bytes,
                    });
                }
                Ok(module)
            });
        drop(compile_permit);

        if started.elapsed() > timeout {
            Err(WasmExecutionError::CompileTimeout {
                timeout_ms: self.limits.compile_timeout.as_millis(),
            })
        } else {
            result
        }
    }
}

fn checked_execution_deadline(
    started: Instant,
    timeout: Duration,
) -> Result<Instant, WasmExecutionError> {
    started.checked_add(timeout).ok_or_else(|| {
        WasmExecutionError::RuntimeSetup(
            "wasm execution timeout exceeds platform Instant range".to_owned(),
        )
    })
}

fn invoke_bounded_host_callback<T>(
    deadline: Instant,
    timed_out: &AtomicBool,
    callback: impl FnOnce() -> Result<T, String>,
) -> Result<T, String> {
    if Instant::now() >= deadline {
        timed_out.store(true, Ordering::Release);
        return Err("wasm host callback started after the execution deadline".to_owned());
    }
    let result = callback();
    if Instant::now() >= deadline {
        timed_out.store(true, Ordering::Release);
        return Err("wasm host callback exceeded the execution deadline".to_owned());
    }
    result
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
    fn runtime_rejects_unbound_host_import_before_instantiation() {
        let directory = tempfile::tempdir().unwrap();
        let plugin_path = write_wat_plugin(
            &directory,
            r#"
            (module
              (import "env" "unexpected_host_call" (func $unexpected (param i32 i32) (result i32)))
              (func (export "decision") (result i32)
                i32.const 0
                i32.const 0
                call $unexpected))
            "#,
        );
        let limits = WasmSandboxLimits::default();
        let plugin =
            load_plugin_file(&plugin_path, &[directory.path().to_path_buf()], limits).unwrap();
        let runtime = FluxWasmRuntime::new(limits).unwrap();
        let module = runtime.compile_plugin_module(&plugin).unwrap();

        let error = runtime
            .run_compiled_i32_no_args(&module, "decision")
            .unwrap_err();

        assert!(matches!(
            error,
            WasmExecutionError::UnsupportedHostImport { module, name }
                if module == "env" && name == "unexpected_host_call"
        ));
    }

    #[cfg(feature = "wasi")]
    #[test]
    fn wasi_randomness_import_requires_explicit_grant() {
        let directory = tempfile::tempdir().unwrap();
        let plugin_path = write_wat_plugin(
            &directory,
            r#"
            (module
              (import "wasi_snapshot_preview1" "random_get"
                (func $random_get (param i32 i32) (result i32)))
              (memory (export "memory") 1)
              (func (export "decision") (result i32)
                i32.const 0
                i32.const 16
                call $random_get))
            "#,
        );
        let limits = WasmSandboxLimits::default();
        let plugin =
            load_plugin_file(&plugin_path, &[directory.path().to_path_buf()], limits).unwrap();
        let runtime = FluxWasmRuntime::new(limits).unwrap();
        let denied = runtime.compile_plugin_module(&plugin).unwrap();

        let error = runtime
            .run_compiled_i32_no_args(&denied, "decision")
            .unwrap_err();
        assert!(matches!(
            error,
            WasmExecutionError::UnsupportedHostImport { module, name }
                if module == "wasi_snapshot_preview1" && name == "random_get"
        ));
        let error = runtime
            .run_compiled_i32_no_args_with_hosts(
                &denied,
                "decision",
                vec![WasmI32HostFunction::new(
                    "wasi_snapshot_preview1",
                    "random_get",
                    |_pointer, _length| Ok(0),
                )],
            )
            .unwrap_err();
        assert!(matches!(
            error,
            WasmExecutionError::UnsupportedHostImport { module, name }
                if module == "wasi_snapshot_preview1" && name == "random_get"
        ));

        let identity = FluxWasmCompiledModuleIdentity::new(
            plugin.sha256_hex(),
            0,
            "test:wasi-preview:randomness",
        )
        .with_wasi_capabilities(WasmWasiCapabilities {
            randomness: true,
            ..WasmWasiCapabilities::default()
        });
        let granted = runtime
            .compile_plugin_module_with_identity(&plugin, identity)
            .unwrap();
        let outcome = runtime
            .run_compiled_i32_no_args(&granted, "decision")
            .unwrap();

        assert_eq!(outcome.result, 0);
    }

    #[cfg(feature = "wasi")]
    #[test]
    fn wasi_clock_import_requires_explicit_grant() {
        let directory = tempfile::tempdir().unwrap();
        let plugin_path = write_wat_plugin(
            &directory,
            r#"
            (module
              (import "wasi_snapshot_preview1" "clock_time_get"
                (func $clock_time_get (param i32 i64 i32) (result i32)))
              (memory (export "memory") 1)
              (func (export "decision") (result i32)
                i32.const 0
                i64.const 1
                i32.const 0
                call $clock_time_get))
            "#,
        );
        let limits = WasmSandboxLimits::default();
        let plugin =
            load_plugin_file(&plugin_path, &[directory.path().to_path_buf()], limits).unwrap();
        let runtime = FluxWasmRuntime::new(limits).unwrap();
        let identity =
            FluxWasmCompiledModuleIdentity::new(plugin.sha256_hex(), 0, "test:wasi-preview:clocks")
                .with_wasi_capabilities(WasmWasiCapabilities {
                    clocks: true,
                    ..WasmWasiCapabilities::default()
                });
        let module = runtime
            .compile_plugin_module_with_identity(&plugin, identity)
            .unwrap();

        let outcome = runtime
            .run_compiled_i32_no_args(&module, "decision")
            .unwrap();

        assert_eq!(outcome.result, 0);
    }

    #[cfg(feature = "wasi")]
    #[test]
    fn wasi_filesystem_and_stdio_imports_remain_denied() {
        let directory = tempfile::tempdir().unwrap();
        let plugin_path = write_wat_plugin(
            &directory,
            r#"
            (module
              (import "wasi_snapshot_preview1" "fd_write"
                (func $fd_write (param i32 i32 i32 i32) (result i32)))
              (memory (export "memory") 1)
              (func (export "decision") (result i32)
                i32.const 1
                i32.const 0
                i32.const 0
                i32.const 0
                call $fd_write))
            "#,
        );
        let limits = WasmSandboxLimits::default();
        let plugin =
            load_plugin_file(&plugin_path, &[directory.path().to_path_buf()], limits).unwrap();
        let runtime = FluxWasmRuntime::new(limits).unwrap();
        let identity = FluxWasmCompiledModuleIdentity::new(
            plugin.sha256_hex(),
            0,
            "test:wasi-preview:bounded",
        )
        .with_wasi_capabilities(WasmWasiCapabilities {
            clocks: true,
            randomness: true,
        });
        let module = runtime
            .compile_plugin_module_with_identity(&plugin, identity)
            .unwrap();

        let error = runtime
            .run_compiled_i32_no_args(&module, "decision")
            .unwrap_err();

        assert!(matches!(
            error,
            WasmExecutionError::UnsupportedHostImport { module, name }
                if module == "wasi_snapshot_preview1" && name == "fd_write"
        ));
    }

    #[cfg(feature = "wasi")]
    #[test]
    fn wasi_randomness_host_call_is_size_bounded() {
        let directory = tempfile::tempdir().unwrap();
        let plugin_path = write_wat_plugin(
            &directory,
            r#"
            (module
              (import "wasi_snapshot_preview1" "random_get"
                (func $random_get (param i32 i32) (result i32)))
              (memory (export "memory") 1)
              (func (export "decision") (result i32)
                i32.const 0
                i32.const 4097
                call $random_get))
            "#,
        );
        let limits = WasmSandboxLimits::default();
        let plugin =
            load_plugin_file(&plugin_path, &[directory.path().to_path_buf()], limits).unwrap();
        let runtime = FluxWasmRuntime::new(limits).unwrap();
        let identity = FluxWasmCompiledModuleIdentity::new(
            plugin.sha256_hex(),
            0,
            "test:wasi-preview:randomness-limit",
        )
        .with_wasi_capabilities(WasmWasiCapabilities {
            randomness: true,
            ..WasmWasiCapabilities::default()
        });
        let module = runtime
            .compile_plugin_module_with_identity(&plugin, identity)
            .unwrap();

        let error = runtime
            .run_compiled_i32_no_args(&module, "decision")
            .unwrap_err();

        assert!(matches!(error, WasmExecutionError::Trap(_)));
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
            cache_identity: FluxWasmCompiledModuleIdentity::new(
                plugin.sha256_hex(),
                FLUXHEIM_WASM_ABI_VERSION,
                "test",
            ),
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
    fn compile_timeout_returns_only_after_releasing_slot() {
        let counter = Box::leak(Box::new(AtomicUsize::new(0)));
        let directory = tempfile::tempdir().unwrap();
        let plugin_path = write_wat_plugin(
            &directory,
            r#"(module (func (export "decision") (result i32) i32.const 7))"#,
        );
        let limits = WasmSandboxLimits {
            compile_timeout: Duration::from_nanos(1),
            ..WasmSandboxLimits::default()
        };
        let plugin =
            load_plugin_file(&plugin_path, &[directory.path().to_path_buf()], limits).unwrap();
        let runtime = FluxWasmRuntime::new(limits).unwrap();

        let error = runtime
            .compile_module_with_counter(&plugin, counter, 1)
            .unwrap_err();

        assert!(matches!(error, WasmExecutionError::CompileTimeout { .. }));
        assert_eq!(counter.load(Ordering::Acquire), 0);
        let permit = acquire_counter_permit(counter, 1).unwrap();
        drop(permit);
    }

    #[test]
    fn runtime_rejects_compiled_artifact_above_limit() {
        let directory = tempfile::tempdir().unwrap();
        let plugin_path = write_wat_plugin(
            &directory,
            r#"(module (func (export "decision") (result i32) i32.const 7))"#,
        );
        let limits = WasmSandboxLimits {
            max_compiled_artifact_bytes: 1,
            ..WasmSandboxLimits::default()
        };
        let plugin =
            load_plugin_file(&plugin_path, &[directory.path().to_path_buf()], limits).unwrap();
        let runtime = FluxWasmRuntime::new(limits).unwrap();

        let error = runtime.compile_plugin_module(&plugin).unwrap_err();

        assert!(matches!(
            error,
            WasmExecutionError::CompiledArtifactOversized { max_bytes: 1 }
        ));
    }

    #[test]
    fn compiled_module_identity_separates_abi_features_and_version() {
        let sha = "a".repeat(64);
        let base = FluxWasmCompiledModuleIdentity::new(&sha, 1, "native-http1:access-decision");
        let different_abi =
            FluxWasmCompiledModuleIdentity::new(&sha, 2, "native-http1:access-decision");
        let different_features =
            FluxWasmCompiledModuleIdentity::new(&sha, 1, "native-http1:cache-store");

        assert_eq!(base.plugin_sha256(), sha);
        assert_eq!(base.abi_version(), 1);
        assert_eq!(base.fluxheim_version(), env!("CARGO_PKG_VERSION"));
        assert_eq!(base.feature_set(), "native-http1:access-decision");
        assert_ne!(base, different_abi);
        assert_ne!(base, different_features);
        assert_ne!(
            base,
            FluxWasmCompiledModuleIdentity::new(&sha, 1, "native-http1:access-decision")
                .with_wasi_capabilities(WasmWasiCapabilities {
                    clocks: true,
                    ..WasmWasiCapabilities::default()
                })
        );
    }

    #[test]
    fn compile_rejects_mismatched_module_identity_digest() {
        let plugin_a_directory = tempfile::tempdir().unwrap();
        let plugin_a_path = write_wat_plugin(
            &plugin_a_directory,
            r#"(module (func (export "decision") (result i32) i32.const 7))"#,
        );
        let plugin_b_directory = tempfile::tempdir().unwrap();
        let plugin_b_path = write_wat_plugin(
            &plugin_b_directory,
            r#"(module (func (export "decision") (result i32) i32.const 8))"#,
        );
        let limits = WasmSandboxLimits::default();
        let plugin_a = load_plugin_file(
            &plugin_a_path,
            &[plugin_a_directory.path().to_path_buf()],
            limits,
        )
        .unwrap();
        let plugin_b = load_plugin_file(
            &plugin_b_path,
            &[plugin_b_directory.path().to_path_buf()],
            limits,
        )
        .unwrap();
        let runtime = FluxWasmRuntime::new(limits).unwrap();
        let identity = FluxWasmCompiledModuleIdentity::new(
            plugin_b.sha256_hex(),
            FLUXHEIM_WASM_ABI_VERSION,
            "test",
        );

        let error = runtime
            .compile_plugin_module_with_identity(&plugin_a, identity)
            .unwrap_err();

        assert!(matches!(error, WasmExecutionError::RuntimeSetup(_)));
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
            fuel: crate::HARD_MAX_FUEL,
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
    fn runtime_rejects_host_callback_result_after_execution_deadline() {
        let directory = tempfile::tempdir().unwrap();
        let plugin_path = write_wat_plugin(
            &directory,
            r#"
            (module
              (import "fluxheim" "slow" (func $slow (param i32 i32) (result i32)))
              (func (export "decision") (result i32)
                i32.const 1
                i32.const 2
                call $slow))
            "#,
        );
        let limits = WasmSandboxLimits {
            timeout: Duration::from_millis(5),
            ..WasmSandboxLimits::default()
        };
        let plugin =
            load_plugin_file(&plugin_path, &[directory.path().to_path_buf()], limits).unwrap();
        let runtime = FluxWasmRuntime::new(limits).unwrap();
        let module = runtime.compile_plugin_module(&plugin).unwrap();

        let error = runtime
            .run_compiled_i32_no_args_with_hosts(
                &module,
                "decision",
                vec![WasmI32HostFunction::new(
                    "fluxheim",
                    "slow",
                    |_left, _right| {
                        thread::sleep(Duration::from_millis(15));
                        Ok(7)
                    },
                )],
            )
            .unwrap_err();

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

    #[test]
    fn admission_controller_rejects_tokio_semaphore_overflow() {
        assert_eq!(
            FluxWasmAdmissionController::new(Semaphore::MAX_PERMITS + 1).unwrap_err(),
            WasmAdmissionError::InvalidLimit
        );
        assert_eq!(
            FluxWasmAdmissionController::new_with_queue(Semaphore::MAX_PERMITS, 1).unwrap_err(),
            WasmAdmissionError::InvalidLimit
        );
    }

    #[test]
    fn execution_deadline_rejects_platform_instant_overflow() {
        assert!(matches!(
            checked_execution_deadline(Instant::now(), Duration::MAX),
            Err(WasmExecutionError::RuntimeSetup(message))
                if message.contains("Instant range")
        ));
    }

    #[test]
    fn admission_controller_bounds_and_releases_queued_executions() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let controller = FluxWasmAdmissionController::new_with_queue(1, 1).unwrap();
            let active = controller.try_acquire().unwrap();
            let queued_controller = controller.clone();
            let queued = tokio::spawn(async move { queued_controller.acquire().await });

            while controller.queued_executions() == 0 {
                tokio::task::yield_now().await;
            }
            let error = controller.acquire().await.unwrap_err();
            assert_eq!(error, WasmAdmissionError::QueueFull);

            drop(active);
            let admitted = queued.await.unwrap().unwrap();
            assert_eq!(controller.active_executions(), 1);
            assert_eq!(controller.queued_executions(), 0);
            drop(admitted);
            assert_eq!(controller.active_executions(), 0);
        });
    }

    #[test]
    fn admission_controller_wakes_all_queued_executions_without_lost_notifications() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        runtime.block_on(async {
            let controller = FluxWasmAdmissionController::new_with_queue(1, 4).unwrap();
            let active = controller.try_acquire().unwrap();
            let mut jobs = Vec::new();
            for _ in 0..4 {
                let queued = controller.clone();
                jobs.push(tokio::spawn(async move {
                    let permit = queued.acquire().await.unwrap();
                    drop(permit);
                }));
            }
            while controller.queued_executions() < 4 {
                tokio::task::yield_now().await;
            }

            drop(active);
            tokio::time::timeout(Duration::from_secs(1), async {
                for job in jobs {
                    job.await.unwrap();
                }
            })
            .await
            .unwrap();

            assert_eq!(controller.active_executions(), 0);
            assert_eq!(controller.queued_executions(), 0);
        });
    }
}
