use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::ConfigError;
#[cfg(any(feature = "metrics-otlp", feature = "otel-otlp"))]
use crate::config_http::{
    valid_http_otlp_endpoint, valid_service_name, validate_otlp_ca_cert_path,
};

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_metrics_listen")]
    pub listen: String,
    #[serde(default = "default_metrics_require_loopback")]
    pub require_loopback: bool,
    #[serde(default)]
    pub otlp: MetricsOtlpExportConfig,
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            listen: default_metrics_listen(),
            require_loopback: default_metrics_require_loopback(),
            otlp: MetricsOtlpExportConfig::default(),
        }
    }
}

impl MetricsConfig {
    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        self.otlp.resolve_relative_paths(base_dir);
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        let listen = self.listen.parse::<SocketAddr>().map_err(|_| {
            ConfigError::InvalidMetricsListenAddress {
                address: self.listen.clone(),
            }
        })?;

        if self.enabled && self.require_loopback && !listen.ip().is_loopback() {
            return Err(ConfigError::MetricsListenNotLoopback {
                address: self.listen.clone(),
            });
        }
        if !self.enabled && self.otlp.enabled {
            return Err(ConfigError::InvalidMetricsPolicy {
                field: "metrics.otlp.enabled",
                reason: "OTLP metrics export requires metrics.enabled = true",
            });
        }
        self.otlp.validate()?;

        Ok(())
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsOtlpExportConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_metrics_otlp_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_metrics_otlp_service_name")]
    pub service_name: String,
    #[serde(default = "default_metrics_otlp_interval_secs")]
    pub interval_secs: u64,
    #[serde(default = "default_metrics_otlp_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub tls_ca_cert_path: Option<PathBuf>,
}

impl Default for MetricsOtlpExportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_metrics_otlp_endpoint(),
            service_name: default_metrics_otlp_service_name(),
            interval_secs: default_metrics_otlp_interval_secs(),
            timeout_secs: default_metrics_otlp_timeout_secs(),
            tls_ca_cert_path: None,
        }
    }
}

impl MetricsOtlpExportConfig {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(path) = &mut self.tls_ca_cert_path
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }

        #[cfg(not(feature = "metrics-otlp"))]
        return Err(ConfigError::MetricsOtlpExportNotCompiled);

        #[cfg(feature = "metrics-otlp")]
        {
            if !valid_http_otlp_endpoint(&self.endpoint) {
                return Err(ConfigError::InvalidMetricsPolicy {
                    field: "metrics.otlp.endpoint",
                    reason: "OTLP metrics export requires an http://host[:port]/path or https://host[:port]/path endpoint without query, fragment, or credentials",
                });
            }
            warn_plaintext_remote_otlp_endpoint("metrics.otlp.endpoint", &self.endpoint);
            validate_otlp_ca_cert_path(
                "metrics.otlp.tls_ca_cert_path",
                self.tls_ca_cert_path.as_deref(),
            )
            .map_err(|reason| ConfigError::InvalidMetricsPolicy {
                field: "metrics.otlp.tls_ca_cert_path",
                reason,
            })?;
            if !valid_service_name(&self.service_name) {
                return Err(ConfigError::InvalidMetricsPolicy {
                    field: "metrics.otlp.service_name",
                    reason: "service name must be 1..=128 visible ASCII bytes without control characters",
                });
            }
            if self.interval_secs == 0 || self.interval_secs > 3600 {
                return Err(ConfigError::InvalidMetricsPolicy {
                    field: "metrics.otlp.interval_secs",
                    reason: "interval must be between 1 and 3600 seconds",
                });
            }
            if self.timeout_secs == 0 || self.timeout_secs > 60 {
                return Err(ConfigError::InvalidMetricsPolicy {
                    field: "metrics.otlp.timeout_secs",
                    reason: "timeout must be between 1 and 60 seconds",
                });
            }
            Ok(())
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TracingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: TracingMode,
    #[serde(default = "default_true")]
    pub traceparent: bool,
    #[serde(default = "default_true")]
    pub log_trace_id: bool,
    #[serde(default)]
    pub otlp: OtlpTraceExportConfig,
}

impl Default for TracingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: TracingMode::default(),
            traceparent: true,
            log_trace_id: true,
            otlp: OtlpTraceExportConfig::default(),
        }
    }
}

impl TracingConfig {
    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        self.otlp.resolve_relative_paths(base_dir);
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        #[cfg(not(feature = "otel-tracing"))]
        if self.enabled {
            return Err(ConfigError::TracingNotCompiled);
        }

        #[cfg(feature = "privacy-mode")]
        if self.enabled {
            return Err(ConfigError::PrivacyModeTracing);
        }

        if self.enabled && self.mode == TracingMode::Off {
            return Err(ConfigError::InvalidTracingPolicy {
                field: "tracing.mode",
                reason: "tracing.enabled requires tracing.mode other than off",
            });
        }
        if !self.enabled && self.otlp.enabled {
            return Err(ConfigError::InvalidTracingPolicy {
                field: "tracing.otlp.enabled",
                reason: "OTLP trace export requires tracing.enabled = true",
            });
        }
        if !self.enabled {
            return Ok(());
        }
        if !self.traceparent && self.mode == TracingMode::PropagateOnly {
            return Err(ConfigError::InvalidTracingPolicy {
                field: "tracing.traceparent",
                reason: "propagate_only mode requires traceparent propagation",
            });
        }
        self.otlp.validate()?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum TracingMode {
    Off,
    #[default]
    PropagateOnly,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OtlpTraceExportConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_otlp_trace_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_otlp_service_name")]
    pub service_name: String,
    #[serde(default = "default_otlp_queue_size")]
    pub queue_size: usize,
    #[serde(default = "default_otlp_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default)]
    pub tls_ca_cert_path: Option<PathBuf>,
}

impl Default for OtlpTraceExportConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_otlp_trace_endpoint(),
            service_name: default_otlp_service_name(),
            queue_size: default_otlp_queue_size(),
            timeout_secs: default_otlp_timeout_secs(),
            tls_ca_cert_path: None,
        }
    }
}

impl OtlpTraceExportConfig {
    fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(path) = &mut self.tls_ca_cert_path
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
    }

    fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }

        #[cfg(not(feature = "otel-otlp"))]
        return Err(ConfigError::OtlpTraceExportNotCompiled);

        #[cfg(feature = "otel-otlp")]
        {
            if !valid_http_otlp_endpoint(&self.endpoint) {
                return Err(ConfigError::InvalidTracingPolicy {
                    field: "tracing.otlp.endpoint",
                    reason: "OTLP trace export requires an http://host[:port]/path or https://host[:port]/path endpoint without query, fragment, or credentials",
                });
            }
            warn_plaintext_remote_otlp_endpoint("tracing.otlp.endpoint", &self.endpoint);
            validate_otlp_ca_cert_path(
                "tracing.otlp.tls_ca_cert_path",
                self.tls_ca_cert_path.as_deref(),
            )
            .map_err(|reason| ConfigError::InvalidTracingPolicy {
                field: "tracing.otlp.tls_ca_cert_path",
                reason,
            })?;
            if !valid_service_name(&self.service_name) {
                return Err(ConfigError::InvalidTracingPolicy {
                    field: "tracing.otlp.service_name",
                    reason: "service name must be 1..=128 visible ASCII bytes without control characters",
                });
            }
            if self.queue_size == 0 || self.queue_size > 1_000_000 {
                return Err(ConfigError::InvalidTracingPolicy {
                    field: "tracing.otlp.queue_size",
                    reason: "queue size must be between 1 and 1,000,000",
                });
            }
            if self.timeout_secs == 0 || self.timeout_secs > 60 {
                return Err(ConfigError::InvalidTracingPolicy {
                    field: "tracing.otlp.timeout_secs",
                    reason: "timeout must be between 1 and 60 seconds",
                });
            }
            Ok(())
        }
    }
}

fn default_metrics_listen() -> String {
    "127.0.0.1:9091".to_owned()
}

fn default_metrics_require_loopback() -> bool {
    true
}

fn default_metrics_otlp_endpoint() -> String {
    "http://127.0.0.1:9090/api/v1/otlp/v1/metrics".to_owned()
}

fn default_metrics_otlp_service_name() -> String {
    "fluxheim".to_owned()
}

fn default_metrics_otlp_interval_secs() -> u64 {
    15
}

fn default_metrics_otlp_timeout_secs() -> u64 {
    2
}

fn default_otlp_trace_endpoint() -> String {
    "http://127.0.0.1:4318/v1/traces".to_owned()
}

fn default_otlp_service_name() -> String {
    "fluxheim".to_owned()
}

fn default_otlp_queue_size() -> usize {
    8192
}

fn default_otlp_timeout_secs() -> u64 {
    2
}

fn default_true() -> bool {
    true
}

#[cfg(any(feature = "metrics-otlp", feature = "otel-otlp"))]
fn warn_plaintext_remote_otlp_endpoint(field: &str, endpoint: &str) {
    if crate::otlp_http::plaintext_non_loopback_endpoint(endpoint) {
        log::warn!(
            "{field} uses plaintext HTTP to a non-loopback host; use https:// or restrict OTLP export to a local collector"
        );
    }
}
