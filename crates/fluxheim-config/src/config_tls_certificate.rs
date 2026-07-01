use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::ConfigError;
use crate::config_path::{validate_non_world_writable_parent, validate_path};

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StaticCertificateConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
}

impl StaticCertificateConfig {
    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if self.cert_path.is_relative() {
            self.cert_path = base_dir.join(&self.cert_path);
        }
        if self.key_path.is_relative() {
            self.key_path = base_dir.join(&self.key_path);
        }
    }

    pub fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        if self.cert_path.as_os_str().is_empty() {
            return Err(ConfigError::EmptyTlsCertificatePath { scope });
        }
        if self.key_path.as_os_str().is_empty() {
            return Err(ConfigError::EmptyTlsKeyPath { scope });
        }
        let cert_field = format!("{scope}.cert_path");
        let key_field = format!("{scope}.key_path");
        validate_path(cert_field.clone(), Some(&self.cert_path))?;
        validate_path(key_field.clone(), Some(&self.key_path))?;
        validate_non_world_writable_parent(cert_field, Some(&self.cert_path))?;
        validate_non_world_writable_parent(key_field, Some(&self.key_path))?;

        Ok(())
    }
}
