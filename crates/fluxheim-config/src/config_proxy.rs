use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::{ByteSize, ConfigError, LoadBalanceConfig, validate_optional_timeout_secs};
use crate::config_net::{upstream_host, valid_authority};
pub use crate::config_proxy_auth::{AuthRequestConfig, AuthRequestConfigFragment};
use crate::config_proxy_discovery::{
    default_proxy_upstreams_file_refresh_secs, default_proxy_upstreams_http_refresh_secs,
    validate_proxy_upstream_discovery,
};
pub use crate::config_proxy_error_page::ProxyErrorPageConfig;
pub use crate::config_proxy_fragment::ProxyConfigFragment;
pub use crate::config_proxy_protocol::{UpstreamHttpVersion, UpstreamProxyProtocol};
pub use crate::config_proxy_traffic_mirror::{TrafficMirrorConfig, TrafficMirrorConfigFragment};
use crate::config_proxy_transport::validate_proxy_upstream_transport;
use crate::config_proxy_upstream_attributes::validate_static_upstream_attributes;
#[cfg(feature = "load-balancer")]
use crate::config_proxy_upstream_policy::validate_load_balancer_backend_keys;
use crate::config_proxy_upstream_policy::validate_upstream_policy;

const DEFAULT_UPSTREAM: &str = "127.0.0.1:3000";

fn default_true() -> bool {
    true
}

fn default_upstream() -> String {
    DEFAULT_UPSTREAM.to_owned()
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfig {
    #[serde(default)]
    pub upstream: Option<String>,
    #[serde(default)]
    pub upstreams: Vec<String>,
    #[serde(default)]
    pub upstreams_file: Option<PathBuf>,
    #[serde(default = "default_proxy_upstreams_file_refresh_secs")]
    pub upstreams_file_refresh_secs: u64,
    #[serde(default)]
    pub upstreams_http_url: Option<String>,
    #[serde(default = "default_proxy_upstreams_http_refresh_secs")]
    pub upstreams_http_refresh_secs: u64,
    #[serde(default)]
    pub upstreams_http_bearer_token_file: Option<PathBuf>,
    #[serde(default)]
    pub upstreams_http_allow_private_backends: bool,
    #[serde(default)]
    pub upstream_dns_refresh_secs: Option<u64>,
    #[serde(default)]
    pub upstream_dns_allow_private_backends: bool,
    #[serde(default)]
    pub upstream_weights: Vec<usize>,
    #[serde(default)]
    pub upstream_priority_groups: Vec<u16>,
    #[serde(default = "default_upstream_priority_group_min_active")]
    pub upstream_priority_group_min_active: usize,
    #[serde(default)]
    pub upstream_localities: Vec<String>,
    #[serde(default)]
    pub preferred_upstream_localities: Vec<String>,
    #[serde(default)]
    pub upstream_max_in_flight: Vec<usize>,
    #[serde(default)]
    pub upstream_aliases: Vec<String>,
    #[serde(default)]
    pub upstream_tags: Vec<Vec<String>>,
    #[serde(default)]
    pub backup_upstreams: Vec<String>,
    #[serde(default)]
    pub drain_upstreams: Vec<String>,
    #[serde(default)]
    pub disabled_upstreams: Vec<String>,
    #[serde(default)]
    pub upstream_tls: bool,
    #[serde(default)]
    pub upstream_sni: Option<String>,
    #[serde(default = "default_true")]
    pub upstream_verify_cert: bool,
    #[serde(default = "default_true")]
    pub upstream_verify_hostname: bool,
    #[serde(default)]
    pub upstream_alternative_cn: Option<String>,
    #[serde(default)]
    pub upstream_ca_path: Option<PathBuf>,
    #[serde(default)]
    pub upstream_client_cert_path: Option<PathBuf>,
    #[serde(default)]
    pub upstream_client_key_path: Option<PathBuf>,
    #[serde(default)]
    pub upstream_proxy_protocol: UpstreamProxyProtocol,
    #[serde(default)]
    pub upstream_http_version: UpstreamHttpVersion,
    #[serde(default)]
    pub upstream_h2c_upgrade: bool,
    #[serde(default)]
    pub websocket: bool,
    #[serde(default)]
    pub auth_request: AuthRequestConfig,
    #[serde(default)]
    pub mirror: TrafficMirrorConfig,
    #[serde(default)]
    pub upstream_h2_max_streams: Option<usize>,
    #[serde(default)]
    pub upstream_h2_ping_interval_secs: Option<u64>,
    #[serde(default)]
    pub connect_timeout_secs: Option<u64>,
    #[serde(default)]
    pub upstream_total_connection_timeout_secs: Option<u64>,
    #[serde(default)]
    pub upstream_idle_timeout_secs: Option<u64>,
    #[serde(default)]
    pub upstream_tcp_keepalive_idle_secs: Option<u64>,
    #[serde(default)]
    pub upstream_tcp_keepalive_interval_secs: Option<u64>,
    #[serde(default)]
    pub upstream_tcp_keepalive_count: Option<usize>,
    #[serde(default)]
    pub upstream_tcp_user_timeout_ms: Option<u64>,
    #[serde(default)]
    pub upstream_tcp_recv_buffer_bytes: Option<ByteSize>,
    #[serde(default)]
    pub upstream_dscp: Option<u8>,
    #[serde(default)]
    pub upstream_tcp_fast_open: bool,
    #[serde(default)]
    pub read_timeout_secs: Option<u64>,
    #[serde(default)]
    pub send_timeout_secs: Option<u64>,
    #[serde(default = "default_proxy_downstream_read_timeout_secs")]
    pub downstream_read_timeout_secs: Option<u64>,
    #[serde(default = "default_proxy_downstream_write_timeout_secs")]
    pub downstream_write_timeout_secs: Option<u64>,
    #[serde(default = "default_proxy_downstream_total_response_timeout_secs")]
    pub downstream_total_response_timeout_secs: Option<u64>,
    #[serde(default)]
    pub downstream_min_send_rate_bytes_per_sec: Option<usize>,
    #[serde(default)]
    pub error_pages: Vec<ProxyErrorPageConfig>,
    #[serde(default)]
    pub load_balance: LoadBalanceConfig,
}

pub const MAX_PROXY_UPSTREAMS: usize = 64;
pub const MAX_PROXY_ERROR_PAGES: usize = 64;
pub const DEFAULT_PROXY_DOWNSTREAM_READ_TIMEOUT_SECS: u64 = 60;
pub const DEFAULT_PROXY_DOWNSTREAM_WRITE_TIMEOUT_SECS: u64 = 30;
pub const DEFAULT_PROXY_DOWNSTREAM_TOTAL_RESPONSE_TIMEOUT_SECS: u64 = 300;

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            upstream: Some(default_upstream()),
            upstreams: Vec::new(),
            upstreams_file: None,
            upstreams_file_refresh_secs: default_proxy_upstreams_file_refresh_secs(),
            upstreams_http_url: None,
            upstreams_http_refresh_secs: default_proxy_upstreams_http_refresh_secs(),
            upstreams_http_bearer_token_file: None,
            upstreams_http_allow_private_backends: false,
            upstream_dns_refresh_secs: None,
            upstream_dns_allow_private_backends: false,
            upstream_weights: Vec::new(),
            upstream_priority_groups: Vec::new(),
            upstream_priority_group_min_active: default_upstream_priority_group_min_active(),
            upstream_localities: Vec::new(),
            preferred_upstream_localities: Vec::new(),
            upstream_max_in_flight: Vec::new(),
            upstream_aliases: Vec::new(),
            upstream_tags: Vec::new(),
            backup_upstreams: Vec::new(),
            drain_upstreams: Vec::new(),
            disabled_upstreams: Vec::new(),
            upstream_tls: false,
            upstream_sni: None,
            upstream_verify_cert: true,
            upstream_verify_hostname: true,
            upstream_alternative_cn: None,
            upstream_ca_path: None,
            upstream_client_cert_path: None,
            upstream_client_key_path: None,
            upstream_proxy_protocol: UpstreamProxyProtocol::Off,
            upstream_http_version: UpstreamHttpVersion::Http1,
            upstream_h2c_upgrade: false,
            websocket: false,
            auth_request: AuthRequestConfig::default(),
            mirror: TrafficMirrorConfig::default(),
            upstream_h2_max_streams: None,
            upstream_h2_ping_interval_secs: None,
            connect_timeout_secs: None,
            upstream_total_connection_timeout_secs: None,
            upstream_idle_timeout_secs: None,
            upstream_tcp_keepalive_idle_secs: None,
            upstream_tcp_keepalive_interval_secs: None,
            upstream_tcp_keepalive_count: None,
            upstream_tcp_user_timeout_ms: None,
            upstream_tcp_recv_buffer_bytes: None,
            upstream_dscp: None,
            upstream_tcp_fast_open: false,
            read_timeout_secs: None,
            send_timeout_secs: None,
            downstream_read_timeout_secs: Some(DEFAULT_PROXY_DOWNSTREAM_READ_TIMEOUT_SECS),
            downstream_write_timeout_secs: Some(DEFAULT_PROXY_DOWNSTREAM_WRITE_TIMEOUT_SECS),
            downstream_total_response_timeout_secs: Some(
                DEFAULT_PROXY_DOWNSTREAM_TOTAL_RESPONSE_TIMEOUT_SECS,
            ),
            downstream_min_send_rate_bytes_per_sec: None,
            error_pages: Vec::new(),
            load_balance: LoadBalanceConfig::default(),
        }
    }
}

impl ProxyConfig {
    pub fn merge(&mut self, fragment: ProxyConfigFragment) {
        if let Some(upstream) = fragment.upstream {
            self.upstream = Some(upstream);
            self.upstreams.clear();
            self.upstreams_file = None;
            self.upstreams_http_url = None;
        }
        if let Some(upstreams) = fragment.upstreams {
            self.upstream = None;
            self.upstreams = upstreams;
            self.upstreams_file = None;
            self.upstreams_http_url = None;
        }
        if let Some(upstreams_file) = fragment.upstreams_file {
            self.upstream = None;
            self.upstreams.clear();
            self.upstreams_file = Some(upstreams_file);
            self.upstreams_http_url = None;
        }
        if let Some(refresh_secs) = fragment.upstreams_file_refresh_secs {
            self.upstreams_file_refresh_secs = refresh_secs;
        }
        if let Some(upstreams_http_url) = fragment.upstreams_http_url {
            self.upstream = None;
            self.upstreams.clear();
            self.upstreams_file = None;
            self.upstreams_http_url = Some(upstreams_http_url);
        }
        if let Some(refresh_secs) = fragment.upstreams_http_refresh_secs {
            self.upstreams_http_refresh_secs = refresh_secs;
        }
        if let Some(path) = fragment.upstreams_http_bearer_token_file {
            self.upstreams_http_bearer_token_file = Some(path);
        }
        if let Some(allow_private) = fragment.upstreams_http_allow_private_backends {
            self.upstreams_http_allow_private_backends = allow_private;
        }
        if let Some(refresh_secs) = fragment.upstream_dns_refresh_secs {
            self.upstream_dns_refresh_secs = Some(refresh_secs);
        }
        if let Some(allow_private) = fragment.upstream_dns_allow_private_backends {
            self.upstream_dns_allow_private_backends = allow_private;
        }
        if let Some(weights) = fragment.upstream_weights {
            self.upstream_weights = weights;
        }
        if let Some(groups) = fragment.upstream_priority_groups {
            self.upstream_priority_groups = groups;
        }
        if let Some(min_active) = fragment.upstream_priority_group_min_active {
            self.upstream_priority_group_min_active = min_active;
        }
        if let Some(localities) = fragment.upstream_localities {
            self.upstream_localities = localities;
        }
        if let Some(localities) = fragment.preferred_upstream_localities {
            self.preferred_upstream_localities = localities;
        }
        if let Some(max_in_flight) = fragment.upstream_max_in_flight {
            self.upstream_max_in_flight = max_in_flight;
        }
        if let Some(aliases) = fragment.upstream_aliases {
            self.upstream_aliases = aliases;
        }
        if let Some(tags) = fragment.upstream_tags {
            self.upstream_tags = tags;
        }
        if let Some(upstreams) = fragment.backup_upstreams {
            self.backup_upstreams = upstreams;
        }
        if let Some(upstreams) = fragment.drain_upstreams {
            self.drain_upstreams = upstreams;
        }
        if let Some(upstreams) = fragment.disabled_upstreams {
            self.disabled_upstreams = upstreams;
        }
        if let Some(upstream_tls) = fragment.upstream_tls {
            self.upstream_tls = upstream_tls;
        }
        if let Some(sni) = fragment.upstream_sni {
            self.upstream_sni = Some(sni);
        }
        if let Some(verify_cert) = fragment.upstream_verify_cert {
            self.upstream_verify_cert = verify_cert;
        }
        if let Some(verify_hostname) = fragment.upstream_verify_hostname {
            self.upstream_verify_hostname = verify_hostname;
        }
        if let Some(alternative_cn) = fragment.upstream_alternative_cn {
            self.upstream_alternative_cn = Some(alternative_cn);
        }
        if let Some(path) = fragment.upstream_ca_path {
            self.upstream_ca_path = Some(path);
        }
        if let Some(path) = fragment.upstream_client_cert_path {
            self.upstream_client_cert_path = Some(path);
        }
        if let Some(path) = fragment.upstream_client_key_path {
            self.upstream_client_key_path = Some(path);
        }
        if let Some(proxy_protocol) = fragment.upstream_proxy_protocol {
            self.upstream_proxy_protocol = proxy_protocol;
        }
        if let Some(http_version) = fragment.upstream_http_version {
            self.upstream_http_version = http_version;
        }
        if let Some(h2c_upgrade) = fragment.upstream_h2c_upgrade {
            self.upstream_h2c_upgrade = h2c_upgrade;
        }
        if let Some(websocket) = fragment.websocket {
            self.websocket = websocket;
        }
        if let Some(auth_request) = fragment.auth_request {
            self.auth_request.merge(auth_request);
        }
        if let Some(mirror) = fragment.mirror {
            self.mirror.merge(mirror);
        }
        if let Some(streams) = fragment.upstream_h2_max_streams {
            self.upstream_h2_max_streams = Some(streams);
        }
        if let Some(interval_secs) = fragment.upstream_h2_ping_interval_secs {
            self.upstream_h2_ping_interval_secs = Some(interval_secs);
        }
        if let Some(timeout_secs) = fragment.connect_timeout_secs {
            self.connect_timeout_secs = Some(timeout_secs);
        }
        if let Some(timeout_secs) = fragment.upstream_total_connection_timeout_secs {
            self.upstream_total_connection_timeout_secs = Some(timeout_secs);
        }
        if let Some(timeout_secs) = fragment.upstream_idle_timeout_secs {
            self.upstream_idle_timeout_secs = Some(timeout_secs);
        }
        if let Some(timeout_secs) = fragment.upstream_tcp_keepalive_idle_secs {
            self.upstream_tcp_keepalive_idle_secs = Some(timeout_secs);
        }
        if let Some(timeout_secs) = fragment.upstream_tcp_keepalive_interval_secs {
            self.upstream_tcp_keepalive_interval_secs = Some(timeout_secs);
        }
        if let Some(count) = fragment.upstream_tcp_keepalive_count {
            self.upstream_tcp_keepalive_count = Some(count);
        }
        if let Some(timeout_ms) = fragment.upstream_tcp_user_timeout_ms {
            self.upstream_tcp_user_timeout_ms = Some(timeout_ms);
        }
        if let Some(bytes) = fragment.upstream_tcp_recv_buffer_bytes {
            self.upstream_tcp_recv_buffer_bytes = Some(bytes);
        }
        if let Some(dscp) = fragment.upstream_dscp {
            self.upstream_dscp = Some(dscp);
        }
        if let Some(tcp_fast_open) = fragment.upstream_tcp_fast_open {
            self.upstream_tcp_fast_open = tcp_fast_open;
        }
        if let Some(timeout_secs) = fragment.read_timeout_secs {
            self.read_timeout_secs = Some(timeout_secs);
        }
        if let Some(timeout_secs) = fragment.send_timeout_secs {
            self.send_timeout_secs = Some(timeout_secs);
        }
        if let Some(timeout_secs) = fragment.downstream_read_timeout_secs {
            self.downstream_read_timeout_secs = Some(timeout_secs);
        }
        if let Some(timeout_secs) = fragment.downstream_write_timeout_secs {
            self.downstream_write_timeout_secs = Some(timeout_secs);
        }
        if let Some(timeout_secs) = fragment.downstream_total_response_timeout_secs {
            self.downstream_total_response_timeout_secs = Some(timeout_secs);
        }
        if let Some(rate) = fragment.downstream_min_send_rate_bytes_per_sec {
            self.downstream_min_send_rate_bytes_per_sec = Some(rate);
        }
        if let Some(error_pages) = fragment.error_pages {
            self.error_pages = error_pages;
        }
        if let Some(load_balance) = fragment.load_balance {
            self.load_balance.merge(load_balance);
        }
    }

    pub fn disabled() -> Self {
        Self {
            upstream: None,
            ..Self::default()
        }
    }

    pub fn has_configured_upstream(&self) -> bool {
        self.upstream.is_some()
            || !self.upstreams.is_empty()
            || self.upstreams_file.is_some()
            || self.upstreams_http_url.is_some()
    }

    pub fn configured_primary_upstream(&self) -> Option<&str> {
        self.upstreams
            .first()
            .map(String::as_str)
            .or(self.upstream.as_deref())
    }

    pub fn primary_upstream(&self) -> &str {
        self.configured_primary_upstream()
            .unwrap_or(DEFAULT_UPSTREAM)
    }

    pub fn upstream_sni(&self) -> String {
        self.upstream_sni
            .clone()
            .unwrap_or_else(|| upstream_host(self.primary_upstream()).unwrap_or_default())
    }

    pub fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(path) = &mut self.upstream_ca_path
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
        if let Some(path) = &mut self.upstreams_file
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
        if let Some(path) = &mut self.upstreams_http_bearer_token_file
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
        if let Some(path) = &mut self.load_balance.runtime_state_file
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
        if let Some(path) = &mut self.upstream_client_cert_path
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
        if let Some(path) = &mut self.upstream_client_key_path
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
        for error_page in &mut self.error_pages {
            error_page.resolve_relative_paths(base_dir);
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        validate_proxy_upstream_discovery(self)?;
        if self.upstreams.len() > MAX_PROXY_UPSTREAMS {
            return Err(ConfigError::TooManyProxyUpstreams {
                max: MAX_PROXY_UPSTREAMS,
            });
        }
        validate_static_upstream_attributes(self)?;
        if self.error_pages.len() > MAX_PROXY_ERROR_PAGES {
            return Err(ConfigError::TooManyProxyErrorPages {
                max: MAX_PROXY_ERROR_PAGES,
            });
        }

        if let Some(upstream) = &self.upstream
            && !valid_authority(upstream)
        {
            return Err(ConfigError::InvalidUpstream {
                address: upstream.clone(),
            });
        }

        let mut seen_upstreams = std::collections::HashSet::new();
        for upstream in &self.upstreams {
            if !valid_authority(upstream) {
                return Err(ConfigError::InvalidUpstream {
                    address: upstream.clone(),
                });
            }
            if !seen_upstreams.insert(upstream.to_ascii_lowercase()) {
                return Err(ConfigError::DuplicateProxyUpstream {
                    upstream: upstream.clone(),
                });
            }
        }
        #[cfg(feature = "load-balancer")]
        validate_load_balancer_backend_keys(&self.upstreams)?;
        validate_upstream_policy(self)?;

        validate_proxy_upstream_transport(self, DEFAULT_UPSTREAM)?;
        self.auth_request.validate("proxy.auth_request")?;
        self.mirror.validate("proxy.mirror")?;
        validate_optional_timeout_secs("proxy.read_timeout_secs", self.read_timeout_secs)?;
        validate_optional_timeout_secs("proxy.send_timeout_secs", self.send_timeout_secs)?;
        validate_optional_timeout_secs(
            "proxy.downstream_read_timeout_secs",
            self.downstream_read_timeout_secs,
        )?;
        validate_optional_timeout_secs(
            "proxy.downstream_write_timeout_secs",
            self.downstream_write_timeout_secs,
        )?;
        validate_optional_timeout_secs(
            "proxy.downstream_total_response_timeout_secs",
            self.downstream_total_response_timeout_secs,
        )?;
        if self
            .downstream_min_send_rate_bytes_per_sec
            .is_some_and(|rate| rate == 0)
        {
            return Err(ConfigError::InvalidProxyTimeout {
                field: "proxy.downstream_min_send_rate_bytes_per_sec",
            });
        }

        let mut statuses = std::collections::HashSet::new();
        for error_page in &self.error_pages {
            error_page.validate()?;
            if !statuses.insert(error_page.status) {
                return Err(ConfigError::DuplicateProxyErrorPageStatus {
                    status: error_page.status,
                });
            }
        }

        self.load_balance.validate()?;
        if self.load_balance.selection.uses_static_ring()
            && (self.upstreams_file.is_some()
                || self.upstreams_http_url.is_some()
                || self.upstream_dns_refresh_secs.is_some())
        {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "static-ring selections require a static proxy.upstreams pool; file, HTTP, and DNS discovery pools rebuild membership dynamically",
            });
        }
        Ok(())
    }
}

fn default_proxy_downstream_read_timeout_secs() -> Option<u64> {
    Some(DEFAULT_PROXY_DOWNSTREAM_READ_TIMEOUT_SECS)
}

fn default_proxy_downstream_write_timeout_secs() -> Option<u64> {
    Some(DEFAULT_PROXY_DOWNSTREAM_WRITE_TIMEOUT_SECS)
}

fn default_proxy_downstream_total_response_timeout_secs() -> Option<u64> {
    Some(DEFAULT_PROXY_DOWNSTREAM_TOTAL_RESPONSE_TIMEOUT_SECS)
}

pub(crate) fn default_upstream_priority_group_min_active() -> usize {
    1
}

#[cfg(all(test, feature = "load-balancer"))]
mod tests {
    use crate::config::ConfigError;
    use crate::config_proxy_upstream_policy::validate_load_balancer_backend_keys;

    #[test]
    fn load_balancer_backend_keys_reject_collisions() {
        let upstreams = vec!["127.0.0.1:3000".to_owned(), "127.0.0.1:3000".to_owned()];

        assert!(matches!(
            validate_load_balancer_backend_keys(&upstreams),
            Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstreams",
                ..
            })
        ));
    }
}
