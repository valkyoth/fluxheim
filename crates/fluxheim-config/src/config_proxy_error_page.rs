use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::ConfigError;
use crate::config_route::validate_route_path;
use crate::config_web::WebConfig;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyErrorPageConfig {
    pub status: u16,
    pub path: String,
    #[serde(default)]
    pub web: WebConfig,
}

impl ProxyErrorPageConfig {
    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        self.web.resolve_relative_paths(base_dir);
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if !(400..=599).contains(&self.status) {
            return Err(ConfigError::InvalidProxyErrorPageStatus {
                status: self.status,
            });
        }
        validate_route_path("proxy.error_pages.path", &self.path, false).map_err(|_| {
            ConfigError::InvalidProxyErrorPagePath {
                path: self.path.clone(),
            }
        })?;
        self.web.validate()?;
        if !self.web.enabled() {
            return Err(ConfigError::MissingProxyErrorPageRoot {
                status: self.status,
            });
        }
        Ok(())
    }
}
