#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use std::time::Duration;

mod file;
mod manifest;
mod policy;
#[cfg(feature = "runtime")]
mod runtime;
pub use file::{WasmPluginError, WasmPluginFile, load_plugin_file, validate_plugin_path};
pub use manifest::{
    LoadedWasmPlugin, ValidatedWasmPluginManifest, WasmHostCallNamespace, WasmManifestError,
    WasmPluginAbi, WasmPluginFailMode, WasmPluginLoadError, WasmPluginManifest, WasmPluginPhase,
    load_plugin_from_manifest, validate_plugin_manifest,
};
pub use policy::{
    WasmAccessChainDecision, WasmAccessDecision, WasmAccessDeny, combine_access_decisions,
};
#[cfg(feature = "runtime")]
pub use runtime::{
    FluxWasmAdmissionController, FluxWasmAdmissionPermit, FluxWasmCompiledModule,
    FluxWasmCompiledModuleIdentity, FluxWasmRuntime, WasmAdmissionError, WasmExecutionError,
    WasmExecutionOutcome, WasmI32HostFunction,
};

pub const FLUXHEIM_WASM_ABI_VERSION: u32 = 1;
pub const DEFAULT_MAX_MODULE_BYTES: u64 = 1_048_576;
pub const DEFAULT_MAX_MEMORY_BYTES: usize = 16 * 1024 * 1024;
pub const DEFAULT_MAX_TABLE_ELEMENTS: usize = 10_000;
pub const DEFAULT_FUEL: u64 = 5_000_000;
pub const DEFAULT_TIMEOUT: Duration = Duration::from_millis(50);
pub const DEFAULT_COMPILE_TIMEOUT: Duration = Duration::from_millis(500);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct WasmSandboxLimits {
    pub max_module_bytes: u64,
    pub max_memory_bytes: usize,
    pub max_table_elements: usize,
    pub fuel: u64,
    pub timeout: Duration,
    pub compile_timeout: Duration,
}

impl Default for WasmSandboxLimits {
    fn default() -> Self {
        Self {
            max_module_bytes: DEFAULT_MAX_MODULE_BYTES,
            max_memory_bytes: DEFAULT_MAX_MEMORY_BYTES,
            max_table_elements: DEFAULT_MAX_TABLE_ELEMENTS,
            fuel: DEFAULT_FUEL,
            timeout: DEFAULT_TIMEOUT,
            compile_timeout: DEFAULT_COMPILE_TIMEOUT,
        }
    }
}

impl WasmSandboxLimits {
    pub fn validate(self) -> Result<Self, WasmPluginError> {
        if self.max_module_bytes == 0 {
            return Err(WasmPluginError::InvalidLimit {
                field: "max_module_bytes",
                reason: "must be greater than zero",
            });
        }
        if self.max_memory_bytes == 0 {
            return Err(WasmPluginError::InvalidLimit {
                field: "max_memory_bytes",
                reason: "must be greater than zero",
            });
        }
        if self.max_table_elements == 0 {
            return Err(WasmPluginError::InvalidLimit {
                field: "max_table_elements",
                reason: "must be greater than zero",
            });
        }
        if self.fuel == 0 {
            return Err(WasmPluginError::InvalidLimit {
                field: "fuel",
                reason: "must be greater than zero",
            });
        }
        if self.timeout.is_zero() {
            return Err(WasmPluginError::InvalidLimit {
                field: "timeout",
                reason: "must be greater than zero",
            });
        }
        if self.compile_timeout.is_zero() {
            return Err(WasmPluginError::InvalidLimit {
                field: "compile_timeout",
                reason: "must be greater than zero",
            });
        }
        Ok(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sandbox_limits_reject_zero_compile_timeout() {
        let error = WasmSandboxLimits {
            compile_timeout: Duration::ZERO,
            ..WasmSandboxLimits::default()
        }
        .validate()
        .unwrap_err();

        assert!(matches!(
            error,
            WasmPluginError::InvalidLimit {
                field: "compile_timeout",
                ..
            }
        ));
    }
}
