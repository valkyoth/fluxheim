use std::fs;
use std::path::Path;

use crate::config::{Config, ConfigError};
use crate::config_fragment::ConfigFragment;
use crate::config_loader::{
    ConfigLoadError, canonical_config_source, config_directory_files, toml_files,
};

impl Config {
    pub fn load(path: Option<&Path>) -> Result<Self, ConfigLoadError> {
        Self::load_with_runtime_path_validation(path, true)
    }

    pub fn load_without_runtime_paths(path: Option<&Path>) -> Result<Self, ConfigLoadError> {
        Self::load_with_runtime_path_validation(path, false)
    }

    fn load_with_runtime_path_validation(
        path: Option<&Path>,
        validate_runtime_paths: bool,
    ) -> Result<Self, ConfigLoadError> {
        let mut config = match path {
            Some(path) => {
                let path = canonical_config_source(path)?;
                if path.is_dir() {
                    Self::load_dir(&path)?
                } else {
                    Self::load_file(&path)?
                }
            }
            None => Self::default(),
        };

        config.apply_presets();
        config
            .validate_with_runtime_path_validation(validate_runtime_paths)
            .map_err(ConfigLoadError::Validate)?;
        Ok(config)
    }

    fn load_file(path: &Path) -> Result<Self, ConfigLoadError> {
        let mut fragment = ConfigFragment::load(path)?;
        let include_conf_d = fragment.include_conf_d;
        let parent = path.parent();
        if let Some(parent) = parent {
            fragment.resolve_relative_paths(parent);
        }

        let mut config = Self::default();
        config.merge(fragment)?;
        if include_conf_d && let Some(parent) = parent {
            config.merge_conf_d(parent)?;
        }
        Ok(config)
    }

    fn load_dir(path: &Path) -> Result<Self, ConfigLoadError> {
        let files = config_directory_files(path)?;

        let mut config = Self::default();
        for file in files {
            let mut fragment = ConfigFragment::load(&file)?;
            if let Some(parent) = file.parent() {
                fragment.resolve_relative_paths(parent);
            }
            config.merge(fragment)?;
        }

        Ok(config)
    }

    fn merge_conf_d(&mut self, base_dir: &Path) -> Result<(), ConfigLoadError> {
        let conf_dir = base_dir.join("conf.d");
        if !conf_dir.try_exists().map_err(ConfigLoadError::Read)? {
            return Ok(());
        }

        let metadata = fs::symlink_metadata(&conf_dir).map_err(ConfigLoadError::Read)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ConfigLoadError::InvalidPath { path: conf_dir });
        }

        let mut files = toml_files(&conf_dir)?;
        files.sort();
        for file in files {
            let mut fragment = ConfigFragment::load(&file)?;
            if let Some(parent) = file.parent() {
                fragment.resolve_relative_paths(parent);
            }
            self.merge(fragment)?;
        }

        Ok(())
    }

    fn apply_presets(&mut self) {
        self.cache.apply_preset_defaults();
        for vhost in &mut self.vhosts {
            vhost.cache.apply_preset_defaults();
            vhost.php.apply_preset_defaults();
            for route in &mut vhost.routes {
                if let Some(cache) = &mut route.cache {
                    cache.apply_preset_defaults();
                }
                if let Some(php) = &mut route.php {
                    php.apply_preset_defaults();
                }
            }
        }
    }

    fn merge(&mut self, fragment: ConfigFragment) -> Result<(), ConfigLoadError> {
        if let Some(server) = fragment.server {
            self.server.merge(server);
        }
        if let Some(admin) = fragment.admin {
            self.admin.merge(admin);
        }
        if let Some(metrics) = fragment.metrics {
            self.metrics = metrics;
        }
        if let Some(tracing) = fragment.tracing {
            self.tracing = tracing;
        }
        if let Some(logging) = fragment.logging {
            self.logging = logging;
        }
        if let Some(headers) = fragment.headers {
            self.headers = headers;
        }
        if let Some(tls) = fragment.tls {
            self.tls.merge(tls);
        }
        if let Some(proxy) = fragment.proxy {
            if proxy.has_conflicting_upstream_sources() {
                return Err(ConfigLoadError::Validate(
                    ConfigError::ConflictingProxyUpstreams,
                ));
            }
            self.proxy.merge(proxy);
        }
        if let Some(compression) = fragment.compression {
            self.compression.merge(compression);
        }
        if let Some(cache) = fragment.cache {
            self.cache.merge(cache);
        }
        if let Some(cache_purger) = fragment.cache_purger {
            self.cache_purger.merge(cache_purger);
        }
        if let Some(web) = fragment.web {
            self.web.merge(web);
        }
        if let Some(geoip) = fragment.geoip {
            self.geoip = geoip;
        }
        if let Some(stream) = fragment.stream {
            self.stream.merge(stream);
        }
        if let Some(udp) = fragment.udp {
            self.udp = udp;
        }
        self.vhosts.extend(fragment.vhosts);
        Ok(())
    }
}
