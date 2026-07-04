use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::config::{
    ConfigLoadError, GeoIpConfig, HeaderPolicyConfig, LoggingConfig, MetricsConfig, TracingConfig,
    UdpConfig, VhostConfig,
};
use crate::config_admin::AdminConfigFragment;
use crate::config_cache::CacheConfigFragment;
use crate::config_cache_purger::CachePurgerConfigFragment;
use crate::config_compression::CompressionConfigFragment;
use crate::config_loader::{read_regular_config_file_to_string, regular_visible_toml_file};
use crate::config_proxy::ProxyConfigFragment;
use crate::config_server::ServerConfigFragment;
use crate::config_stream::StreamConfigFragment;
use crate::config_tls::TlsConfigFragment;
use crate::config_wasm::WasmConfigFragment;
use crate::config_web::WebConfigFragment;

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ConfigFragment {
    #[serde(default)]
    pub(crate) include_conf_d: bool,
    #[serde(default)]
    pub(crate) server: Option<ServerConfigFragment>,
    #[serde(default)]
    pub(crate) admin: Option<AdminConfigFragment>,
    #[serde(default)]
    pub(crate) metrics: Option<MetricsConfig>,
    #[serde(default)]
    pub(crate) tracing: Option<TracingConfig>,
    #[serde(default)]
    pub(crate) logging: Option<LoggingConfig>,
    #[serde(default)]
    pub(crate) headers: Option<HeaderPolicyConfig>,
    #[serde(default)]
    pub(crate) tls: Option<TlsConfigFragment>,
    #[serde(default)]
    pub(crate) proxy: Option<ProxyConfigFragment>,
    #[serde(default)]
    pub(crate) compression: Option<CompressionConfigFragment>,
    #[serde(default)]
    pub(crate) cache: Option<CacheConfigFragment>,
    #[serde(default)]
    pub(crate) cache_purger: Option<CachePurgerConfigFragment>,
    #[serde(default)]
    pub(crate) web: Option<WebConfigFragment>,
    #[serde(default)]
    pub(crate) geoip: Option<GeoIpConfig>,
    #[serde(default)]
    pub(crate) stream: Option<StreamConfigFragment>,
    #[serde(default)]
    pub(crate) udp: Option<UdpConfig>,
    #[serde(default)]
    pub(crate) wasm: Option<WasmConfigFragment>,
    #[serde(default)]
    pub(crate) vhosts: Vec<VhostConfig>,
}

impl ConfigFragment {
    pub(crate) fn load(path: &Path) -> Result<Self, ConfigLoadError> {
        if !regular_visible_toml_file(path)? {
            return Err(ConfigLoadError::InvalidPath {
                path: path.to_path_buf(),
            });
        }
        let raw = read_regular_config_file_to_string(path)?;
        toml::from_str(&raw).map_err(|source| ConfigLoadError::Parse {
            path: path.to_path_buf(),
            source,
        })
    }

    pub(crate) fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(server) = &mut self.server {
            server.resolve_relative_paths(base_dir);
        }
        if let Some(tls) = &mut self.tls {
            tls.resolve_relative_paths(base_dir);
        }
        if let Some(admin) = &mut self.admin {
            admin.resolve_relative_paths(base_dir);
        }
        if let Some(metrics) = &mut self.metrics {
            metrics.resolve_relative_paths(base_dir);
        }
        if let Some(tracing) = &mut self.tracing {
            tracing.resolve_relative_paths(base_dir);
        }
        if let Some(logging) = &mut self.logging {
            logging.resolve_relative_paths(base_dir);
        }
        if let Some(proxy) = &mut self.proxy {
            proxy.resolve_relative_paths(base_dir);
        }
        if let Some(cache) = &mut self.cache {
            cache.resolve_relative_paths(base_dir);
        }
        if let Some(web) = &mut self.web {
            web.resolve_relative_paths(base_dir);
        }
        if let Some(geoip) = &mut self.geoip {
            geoip.resolve_relative_paths(base_dir);
        }
        if let Some(stream) = &mut self.stream {
            stream.resolve_relative_paths(base_dir);
        }
        if let Some(wasm) = &mut self.wasm {
            wasm.resolve_relative_paths(base_dir);
        }
        for vhost in &mut self.vhosts {
            vhost.resolve_relative_paths(base_dir);
        }
    }
}
