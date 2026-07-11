use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::config::{DownstreamProxyProtocol, UpstreamProxyProtocol};
#[path = "config_stream_impl.rs"]
mod config_stream_impl;
pub use crate::config_stream_defaults::DEFAULT_STREAM_MAX_CONNECTIONS;
use crate::config_stream_defaults::{
    default_stream_connect_timeout_secs, default_stream_idle_timeout_secs,
    default_stream_max_connections, default_true,
};
#[cfg(feature = "stream-proxy")]
pub use crate::config_stream_slots::{StreamConnectionSlot, acquire_stream_connection_slot};

pub const MAX_STREAM_ROUTES: usize = 128;
pub const MAX_STREAM_ROUTE_NAME_BYTES: usize = 128;
pub const MAX_STREAM_LISTENERS: usize = 64;
pub const MAX_STREAM_UPSTREAMS: usize = 64;
pub const MAX_STREAM_SOURCE_MATCHERS: usize = 256;
pub const MAX_STREAM_MAX_CONNECTIONS: usize = 1_000_000;
pub const MAX_STREAM_UPSTREAM_WEIGHT: usize = 1000;
pub const MAX_STREAM_UPSTREAM_TOTAL_WEIGHT: usize = u16::MAX as usize;

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub routes: Vec<StreamRouteConfig>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamConfigFragment {
    enabled: Option<bool>,
    routes: Option<Vec<StreamRouteConfig>>,
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StreamRouteConfig {
    pub name: String,
    #[serde(default)]
    pub listen: Vec<String>,
    #[serde(default)]
    pub upstream: Option<String>,
    #[serde(default)]
    pub upstreams: Vec<String>,
    #[serde(default)]
    pub upstream_weights: Vec<usize>,
    #[serde(default)]
    pub upstream_aliases: Vec<String>,
    #[serde(default)]
    pub backup_upstreams: Vec<String>,
    #[serde(default)]
    pub drain_upstreams: Vec<String>,
    #[serde(default = "default_stream_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_stream_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default)]
    pub max_connection_secs: Option<u64>,
    #[serde(default)]
    pub max_connection_bytes: Option<u64>,
    #[serde(default = "default_stream_max_connections")]
    pub max_connections: usize,
    #[serde(default)]
    pub downstream_proxy_protocol: DownstreamProxyProtocol,
    #[serde(default)]
    pub trusted_proxies: Vec<String>,
    #[serde(default)]
    pub allow_sources: Vec<String>,
    #[serde(default)]
    pub deny_sources: Vec<String>,
    #[serde(default)]
    pub upstream_proxy_protocol: UpstreamProxyProtocol,
    #[serde(default)]
    pub upstream_tls: bool,
    #[serde(default)]
    pub upstream_dns_allow_private_addresses: bool,
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
}

impl Default for StreamRouteConfig {
    fn default() -> Self {
        Self {
            name: String::new(),
            listen: Vec::new(),
            upstream: None,
            upstreams: Vec::new(),
            upstream_weights: Vec::new(),
            upstream_aliases: Vec::new(),
            backup_upstreams: Vec::new(),
            drain_upstreams: Vec::new(),
            connect_timeout_secs: default_stream_connect_timeout_secs(),
            idle_timeout_secs: default_stream_idle_timeout_secs(),
            max_connection_secs: None,
            max_connection_bytes: None,
            max_connections: DEFAULT_STREAM_MAX_CONNECTIONS,
            downstream_proxy_protocol: DownstreamProxyProtocol::default(),
            trusted_proxies: Vec::new(),
            allow_sources: Vec::new(),
            deny_sources: Vec::new(),
            upstream_proxy_protocol: UpstreamProxyProtocol::default(),
            upstream_tls: false,
            upstream_dns_allow_private_addresses: false,
            upstream_sni: None,
            upstream_verify_cert: true,
            upstream_verify_hostname: true,
            upstream_alternative_cn: None,
            upstream_ca_path: None,
            upstream_client_cert_path: None,
            upstream_client_key_path: None,
        }
    }
}
