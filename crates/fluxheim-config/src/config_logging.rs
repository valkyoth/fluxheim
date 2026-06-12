use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::ConfigError;
use crate::config_header::validate_header_name;
use crate::config_path::{validate_non_world_writable_parent, validate_path};

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingConfig {
    #[serde(default)]
    pub level: LoggingLevel,
    #[serde(default)]
    pub format: LoggingFormat,
    #[serde(default)]
    pub target: LoggingTarget,
    #[serde(default)]
    pub file: LoggingFileConfig,
    #[serde(default)]
    pub access: AccessLoggingConfig,
}

impl LoggingConfig {
    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(path) = &mut self.file.path
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        self.file.validate()?;
        self.access.validate()
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoggingFileConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default = "default_true")]
    pub append: bool,
}

impl Default for LoggingFileConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: None,
            append: true,
        }
    }
}

impl LoggingFileConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        #[cfg(feature = "privacy-mode")]
        if self.enabled {
            return Err(ConfigError::PrivacyModeFileLogging);
        }

        if self.enabled && self.path.is_none() {
            return Err(ConfigError::MissingLoggingFilePath);
        }

        if self
            .path
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(ConfigError::EmptyLoggingFilePath);
        }

        validate_path("logging.file.path", self.path.as_deref())?;
        validate_non_world_writable_parent("logging.file.path", self.path.as_deref())?;
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LoggingLevel {
    Trace,
    Debug,
    #[default]
    Info,
    Warn,
    Error,
    Off,
}

impl LoggingLevel {
    pub fn as_filter(self) -> &'static str {
        match self {
            Self::Trace => "trace",
            Self::Debug => "debug",
            Self::Info => "info",
            Self::Warn => "warn",
            Self::Error => "error",
            Self::Off => "off",
        }
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LoggingFormat {
    Text,
    #[default]
    Json,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum LoggingTarget {
    Stdout,
    #[default]
    Stderr,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AccessLoggingConfig {
    #[serde(default = "default_access_logging_enabled")]
    pub enabled: bool,
    #[serde(default = "default_true")]
    pub include_host: bool,
    #[serde(default = "default_true")]
    pub include_client_ip: bool,
    #[serde(default = "default_true")]
    pub include_cache_phase: bool,
    #[serde(default = "default_true")]
    pub include_path: bool,
    #[serde(default = "default_true")]
    pub include_route: bool,
    #[serde(default = "default_true")]
    pub include_upstream: bool,
    #[serde(default = "default_true")]
    pub request_id: bool,
    #[serde(default = "default_request_id_header")]
    pub request_id_header: String,
}

impl Default for AccessLoggingConfig {
    fn default() -> Self {
        Self {
            enabled: default_access_logging_enabled(),
            include_host: true,
            include_client_ip: true,
            include_cache_phase: true,
            include_path: true,
            include_route: true,
            include_upstream: true,
            request_id: true,
            request_id_header: default_request_id_header(),
        }
    }
}

impl AccessLoggingConfig {
    fn validate(&self) -> Result<(), ConfigError> {
        #[cfg(feature = "privacy-mode")]
        if self.enabled {
            return Err(ConfigError::PrivacyModeAccessLogging);
        }

        if self.request_id {
            validate_header_name("logging.access.request_id_header", &self.request_id_header)?;
        }

        Ok(())
    }
}

fn default_access_logging_enabled() -> bool {
    !cfg!(feature = "privacy-mode")
}

fn default_request_id_header() -> String {
    "x-request-id".to_owned()
}

fn default_true() -> bool {
    true
}
