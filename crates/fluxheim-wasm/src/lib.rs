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
    WasmWasiCapabilities, load_plugin_from_manifest, validate_plugin_manifest,
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
pub const HARD_MAX_MODULE_BYTES: u64 = 16 * 1024 * 1024;
pub const HARD_MAX_MEMORY_BYTES: usize = 256 * 1024 * 1024;
pub const HARD_MAX_TABLE_ELEMENTS: usize = 100_000;
pub const HARD_MAX_FUEL: u64 = 100_000_000;
pub const HARD_MAX_TIMEOUT: Duration = Duration::from_secs(5);
pub const HARD_MAX_COMPILE_TIMEOUT: Duration = Duration::from_secs(10);

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
        if self.max_module_bytes == 0 || self.max_module_bytes > HARD_MAX_MODULE_BYTES {
            return Err(WasmPluginError::InvalidLimit {
                field: "max_module_bytes",
                reason: "must be between 1 byte and 16 MiB",
            });
        }
        if self.max_memory_bytes == 0 || self.max_memory_bytes > HARD_MAX_MEMORY_BYTES {
            return Err(WasmPluginError::InvalidLimit {
                field: "max_memory_bytes",
                reason: "must be between 1 byte and 256 MiB",
            });
        }
        if self.max_table_elements == 0 || self.max_table_elements > HARD_MAX_TABLE_ELEMENTS {
            return Err(WasmPluginError::InvalidLimit {
                field: "max_table_elements",
                reason: "must be between 1 and 100000",
            });
        }
        if self.fuel == 0 || self.fuel > HARD_MAX_FUEL {
            return Err(WasmPluginError::InvalidLimit {
                field: "fuel",
                reason: "must be between 1 and 100000000",
            });
        }
        if self.timeout.is_zero() || self.timeout > HARD_MAX_TIMEOUT {
            return Err(WasmPluginError::InvalidLimit {
                field: "timeout",
                reason: "must be between 1ns and 5s",
            });
        }
        if self.compile_timeout.is_zero() || self.compile_timeout > HARD_MAX_COMPILE_TIMEOUT {
            return Err(WasmPluginError::InvalidLimit {
                field: "compile_timeout",
                reason: "must be between 1ns and 10s",
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

    #[test]
    fn sandbox_limits_reject_values_above_hard_ceiling() {
        let cases = [
            (
                "max_module_bytes",
                WasmSandboxLimits {
                    max_module_bytes: HARD_MAX_MODULE_BYTES + 1,
                    ..WasmSandboxLimits::default()
                },
            ),
            (
                "max_memory_bytes",
                WasmSandboxLimits {
                    max_memory_bytes: HARD_MAX_MEMORY_BYTES + 1,
                    ..WasmSandboxLimits::default()
                },
            ),
            (
                "max_table_elements",
                WasmSandboxLimits {
                    max_table_elements: HARD_MAX_TABLE_ELEMENTS + 1,
                    ..WasmSandboxLimits::default()
                },
            ),
            (
                "fuel",
                WasmSandboxLimits {
                    fuel: HARD_MAX_FUEL + 1,
                    ..WasmSandboxLimits::default()
                },
            ),
            (
                "timeout",
                WasmSandboxLimits {
                    timeout: HARD_MAX_TIMEOUT + Duration::from_nanos(1),
                    ..WasmSandboxLimits::default()
                },
            ),
            (
                "compile_timeout",
                WasmSandboxLimits {
                    compile_timeout: HARD_MAX_COMPILE_TIMEOUT + Duration::from_nanos(1),
                    ..WasmSandboxLimits::default()
                },
            ),
        ];

        for (field, limits) in cases {
            assert!(matches!(
                limits.validate(),
                Err(WasmPluginError::InvalidLimit {
                    field: invalid,
                    ..
                }) if invalid == field
            ));
        }
    }

    #[test]
    fn sandbox_limits_accept_values_at_hard_ceiling() {
        assert!(
            WasmSandboxLimits {
                max_module_bytes: HARD_MAX_MODULE_BYTES,
                max_memory_bytes: HARD_MAX_MEMORY_BYTES,
                max_table_elements: HARD_MAX_TABLE_ELEMENTS,
                fuel: HARD_MAX_FUEL,
                timeout: HARD_MAX_TIMEOUT,
                compile_timeout: HARD_MAX_COMPILE_TIMEOUT,
            }
            .validate()
            .is_ok()
        );
    }
}
