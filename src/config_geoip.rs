use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::ConfigError;
#[cfg(feature = "geoip")]
use crate::config::validate_config_list_len;

#[cfg(feature = "geoip")]
const MAX_GEOIP_DATABASES: usize = 8;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeoIpConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_geoip_fallback_enabled")]
    pub fallback_enabled: bool,
    #[serde(default)]
    pub databases: Vec<GeoIpDatabaseConfig>,
}

impl Default for GeoIpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            fallback_enabled: default_geoip_fallback_enabled(),
            databases: Vec::new(),
        }
    }
}

impl GeoIpConfig {
    pub(crate) fn resolve_relative_paths(&mut self, base_dir: &Path) {
        for database in &mut self.databases {
            if database.path.is_relative() {
                database.path = base_dir.join(&database.path);
            }
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        #[cfg(not(feature = "geoip"))]
        {
            Err(ConfigError::GeoIpNotCompiled)
        }
        #[cfg(feature = "geoip")]
        {
            validate_config_list_len(
                "geoip.databases".to_owned(),
                self.databases.len(),
                MAX_GEOIP_DATABASES,
            )?;
            if self.databases.is_empty() {
                return Err(ConfigError::InvalidGeoIpPolicy {
                    field: "geoip.databases",
                    reason: "geoip.enabled requires at least one local MMDB database",
                });
            }
            for database in &self.databases {
                database.validate()?;
            }
            Ok(())
        }
    }
}

fn default_geoip_fallback_enabled() -> bool {
    true
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GeoIpDatabaseConfig {
    pub provider: GeoIpProvider,
    pub path: PathBuf,
}

impl GeoIpDatabaseConfig {
    #[cfg(feature = "geoip")]
    fn validate(&self) -> Result<(), ConfigError> {
        if self.path.as_os_str().is_empty() {
            return Err(ConfigError::InvalidGeoIpPolicy {
                field: "geoip.databases.path",
                reason: "database path cannot be empty",
            });
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum GeoIpProvider {
    Maxmind,
    CirclGeoOpen,
}

impl GeoIpProvider {
    #[cfg(feature = "geoip")]
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Maxmind => "maxmind",
            Self::CirclGeoOpen => "circl-geo-open",
        }
    }
}
