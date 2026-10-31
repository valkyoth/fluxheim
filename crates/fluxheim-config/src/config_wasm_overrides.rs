use super::{ByteSize, WasmAdmissionBudgetConfig, WasmSandboxLimitsConfig};
use serde::{Deserialize, Serialize};

/// Present values override the parent; omitted values inherit, even in an empty table.
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WasmSandboxLimitsOverride {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_module_bytes: Option<ByteSize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_compiled_artifact_bytes: Option<ByteSize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_memory_bytes: Option<ByteSize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_table_elements: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fuel: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub compile_timeout_ms: Option<u64>,
}

impl WasmSandboxLimitsOverride {
    pub fn resolve(self, parent: WasmSandboxLimitsConfig) -> WasmSandboxLimitsConfig {
        WasmSandboxLimitsConfig {
            max_module_bytes: self.max_module_bytes.unwrap_or(parent.max_module_bytes),
            max_compiled_artifact_bytes: self
                .max_compiled_artifact_bytes
                .unwrap_or(parent.max_compiled_artifact_bytes),
            max_memory_bytes: self.max_memory_bytes.unwrap_or(parent.max_memory_bytes),
            max_table_elements: self.max_table_elements.unwrap_or(parent.max_table_elements),
            fuel: self.fuel.unwrap_or(parent.fuel),
            timeout_ms: self.timeout_ms.unwrap_or(parent.timeout_ms),
            compile_timeout_ms: self.compile_timeout_ms.unwrap_or(parent.compile_timeout_ms),
        }
    }
}

impl From<WasmSandboxLimitsConfig> for WasmSandboxLimitsOverride {
    fn from(value: WasmSandboxLimitsConfig) -> Self {
        Self {
            max_module_bytes: Some(value.max_module_bytes),
            max_compiled_artifact_bytes: Some(value.max_compiled_artifact_bytes),
            max_memory_bytes: Some(value.max_memory_bytes),
            max_table_elements: Some(value.max_table_elements),
            fuel: Some(value.fuel),
            timeout_ms: Some(value.timeout_ms),
            compile_timeout_ms: Some(value.compile_timeout_ms),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct WasmAdmissionBudgetOverride {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_concurrent_executions: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub queue_limit: Option<u32>,
}

impl WasmAdmissionBudgetOverride {
    pub fn resolve(self, parent: WasmAdmissionBudgetConfig) -> WasmAdmissionBudgetConfig {
        WasmAdmissionBudgetConfig {
            max_concurrent_executions: self
                .max_concurrent_executions
                .unwrap_or(parent.max_concurrent_executions),
            queue_limit: self.queue_limit.unwrap_or(parent.queue_limit),
        }
    }
}

impl From<WasmAdmissionBudgetConfig> for WasmAdmissionBudgetOverride {
    fn from(value: WasmAdmissionBudgetConfig) -> Self {
        Self {
            max_concurrent_executions: Some(value.max_concurrent_executions),
            queue_limit: Some(value.queue_limit),
        }
    }
}
