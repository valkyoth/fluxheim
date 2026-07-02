use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::{ByteSize, LoadBalanceConfig};
pub use crate::config_proxy_auth::{AuthRequestConfig, AuthRequestConfigFragment};
use crate::config_proxy_discovery::{
    default_proxy_upstreams_file_refresh_secs, default_proxy_upstreams_http_refresh_secs,
};
pub use crate::config_proxy_error_page::ProxyErrorPageConfig;
pub use crate::config_proxy_fragment::ProxyConfigFragment;
pub use crate::config_proxy_protocol::{UpstreamHttpVersion, UpstreamProxyProtocol};
pub use crate::config_proxy_traffic_mirror::{TrafficMirrorConfig, TrafficMirrorConfigFragment};

#[path = "config_proxy_defaults.rs"]
mod config_proxy_defaults;
pub(crate) use config_proxy_defaults::default_upstream_priority_group_min_active;
use config_proxy_defaults::{
    DEFAULT_UPSTREAM, default_proxy_downstream_read_timeout_secs,
    default_proxy_downstream_total_response_timeout_secs,
    default_proxy_downstream_write_timeout_secs, default_true, default_upstream,
};
#[path = "config_proxy_impl.rs"]
mod config_proxy_impl;

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
