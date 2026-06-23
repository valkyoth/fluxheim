use std::collections::{BTreeSet, HashSet};
#[cfg(feature = "load-balancer")]
use std::hash::Hasher;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::{
    ByteSize, ConfigError, LoadBalanceConfig, validate_config_list_len,
    validate_optional_timeout_secs, validate_required_timeout_secs,
};
use crate::config_header::validate_header_name;
use crate::config_http::{valid_http_base_url, valid_http_endpoint_url};
use crate::config_load_balance::LB_SAFE_RETRY_METHODS;
use crate::config_load_balance::LoadBalanceConfigFragment;
#[cfg(feature = "load-balancer")]
use crate::config_loader::read_proxy_upstreams_file;
#[cfg(feature = "load-balancer")]
use crate::config_net::http_authority_is_numeric_loopback;
use crate::config_net::{normalize_host, upstream_host, valid_authority, valid_upstream_alias};
use crate::config_path::{validate_non_world_writable_parent, validate_path};
use crate::config_route::validate_route_path;
use crate::config_web::WebConfig;

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

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfigFragment {
    upstream: Option<String>,
    upstreams: Option<Vec<String>>,
    upstreams_file: Option<PathBuf>,
    upstreams_file_refresh_secs: Option<u64>,
    upstreams_http_url: Option<String>,
    upstreams_http_refresh_secs: Option<u64>,
    upstreams_http_bearer_token_file: Option<PathBuf>,
    upstreams_http_allow_private_backends: Option<bool>,
    upstream_dns_refresh_secs: Option<u64>,
    upstream_dns_allow_private_backends: Option<bool>,
    upstream_weights: Option<Vec<usize>>,
    upstream_priority_groups: Option<Vec<u16>>,
    upstream_priority_group_min_active: Option<usize>,
    upstream_localities: Option<Vec<String>>,
    preferred_upstream_localities: Option<Vec<String>>,
    upstream_max_in_flight: Option<Vec<usize>>,
    upstream_aliases: Option<Vec<String>>,
    upstream_tags: Option<Vec<Vec<String>>>,
    backup_upstreams: Option<Vec<String>>,
    drain_upstreams: Option<Vec<String>>,
    disabled_upstreams: Option<Vec<String>>,
    upstream_tls: Option<bool>,
    upstream_sni: Option<String>,
    upstream_verify_cert: Option<bool>,
    upstream_verify_hostname: Option<bool>,
    upstream_alternative_cn: Option<String>,
    upstream_ca_path: Option<PathBuf>,
    upstream_client_cert_path: Option<PathBuf>,
    upstream_client_key_path: Option<PathBuf>,
    upstream_proxy_protocol: Option<UpstreamProxyProtocol>,
    upstream_http_version: Option<UpstreamHttpVersion>,
    upstream_h2c_upgrade: Option<bool>,
    websocket: Option<bool>,
    auth_request: Option<AuthRequestConfigFragment>,
    mirror: Option<TrafficMirrorConfigFragment>,
    upstream_h2_max_streams: Option<usize>,
    upstream_h2_ping_interval_secs: Option<u64>,
    connect_timeout_secs: Option<u64>,
    upstream_total_connection_timeout_secs: Option<u64>,
    upstream_idle_timeout_secs: Option<u64>,
    upstream_tcp_keepalive_idle_secs: Option<u64>,
    upstream_tcp_keepalive_interval_secs: Option<u64>,
    upstream_tcp_keepalive_count: Option<usize>,
    upstream_tcp_user_timeout_ms: Option<u64>,
    upstream_tcp_recv_buffer_bytes: Option<ByteSize>,
    upstream_dscp: Option<u8>,
    upstream_tcp_fast_open: Option<bool>,
    read_timeout_secs: Option<u64>,
    send_timeout_secs: Option<u64>,
    downstream_read_timeout_secs: Option<u64>,
    downstream_write_timeout_secs: Option<u64>,
    downstream_total_response_timeout_secs: Option<u64>,
    downstream_min_send_rate_bytes_per_sec: Option<usize>,
    error_pages: Option<Vec<ProxyErrorPageConfig>>,
    load_balance: Option<LoadBalanceConfigFragment>,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpstreamProxyProtocol {
    #[default]
    Off,
    V1,
    V2,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum UpstreamHttpVersion {
    #[default]
    Http1,
    Http2,
    Http1AndHttp2,
}

pub const MAX_PROXY_UPSTREAMS: usize = 64;
const MIN_PROXY_UPSTREAMS_FILE_REFRESH_SECS: u64 = 1;
const MAX_PROXY_UPSTREAMS_FILE_REFRESH_SECS: u64 = 300;
#[cfg(feature = "load-balancer")]
const MIN_PROXY_UPSTREAM_DNS_REFRESH_SECS: u64 = 1;
#[cfg(feature = "load-balancer")]
const MAX_PROXY_UPSTREAM_DNS_REFRESH_SECS: u64 = 300;
const MAX_PROXY_UPSTREAM_WEIGHT: usize = 1000;
const MAX_PROXY_UPSTREAM_TOTAL_WEIGHT: usize = u16::MAX as usize;
const MAX_PROXY_UPSTREAM_PRIORITY_GROUP: u16 = 1000;
const MAX_PROXY_UPSTREAM_MAX_IN_FLIGHT: usize = 1_000_000;
const MAX_PROXY_UPSTREAM_TAGS_PER_BACKEND: usize = 16;
pub const MAX_PROXY_ERROR_PAGES: usize = 64;
const MAX_PROXY_UPSTREAM_H2_STREAMS: usize = 1024;
const MAX_PROXY_UPSTREAM_TCP_KEEPALIVE_COUNT: usize = 128;
const MAX_PROXY_UPSTREAM_TCP_RECV_BUFFER_BYTES: u64 = 256 * 1024 * 1024;
const MAX_PROXY_UPSTREAM_DSCP: u8 = 63;
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
        let dynamic_discovery_count = usize::from(self.upstreams_file.is_some())
            + usize::from(self.upstreams_http_url.is_some());
        if self.upstream.is_some()
            && (!self.upstreams.is_empty()
                || self.upstreams_file.is_some()
                || self.upstreams_http_url.is_some())
            || !self.upstreams.is_empty()
                && (self.upstreams_file.is_some() || self.upstreams_http_url.is_some())
            || dynamic_discovery_count > 1
        {
            return Err(ConfigError::ConflictingProxyUpstreams);
        }
        if let Some(path) = &self.upstreams_file {
            #[cfg(not(feature = "load-balancer"))]
            {
                let _ = path;
                return Err(ConfigError::InvalidProxyUpstreamPolicy {
                    field: "proxy.upstreams_file",
                    reason: "requires the load-balancer feature",
                });
            }
            #[cfg(feature = "load-balancer")]
            {
                validate_path("proxy.upstreams_file", Some(path))?;
                validate_non_world_writable_parent("proxy.upstreams_file", Some(path))?;
                let upstreams = read_proxy_upstreams_file(path).map_err(|_| {
                    ConfigError::InvalidProxyUpstreamPolicy {
                        field: "proxy.upstreams_file",
                        reason: "must be a readable regular file containing 2-64 unique host:port entries",
                    }
                })?;
                if upstreams.len() < 2 {
                    return Err(ConfigError::InvalidProxyUpstreamPolicy {
                        field: "proxy.upstreams_file",
                        reason: "must contain at least two upstreams",
                    });
                }
                if !self.upstream_weights.is_empty()
                    || !self.upstream_priority_groups.is_empty()
                    || self.upstream_priority_group_min_active
                        != default_upstream_priority_group_min_active()
                    || !self.upstream_localities.is_empty()
                    || !self.preferred_upstream_localities.is_empty()
                    || !self.upstream_max_in_flight.is_empty()
                    || !self.upstream_aliases.is_empty()
                    || !self.upstream_tags.is_empty()
                    || !self.backup_upstreams.is_empty()
                    || !self.drain_upstreams.is_empty()
                    || !self.disabled_upstreams.is_empty()
                {
                    return Err(ConfigError::InvalidProxyUpstreamPolicy {
                        field: "proxy.upstreams_file",
                        reason: "cannot be combined with upstream_weights, upstream_priority_groups, upstream_priority_group_min_active, upstream_localities, preferred_upstream_localities, upstream_max_in_flight, upstream_aliases, upstream_tags, backup_upstreams, drain_upstreams, or disabled_upstreams in this release",
                    });
                }
                if self.upstream_tls && self.upstream_sni.is_none() {
                    return Err(ConfigError::InvalidProxyTlsPolicy {
                        reason: "upstreams_file with upstream_tls requires explicit upstream_sni",
                    });
                }
            }
        }
        if self.upstreams_file.is_some()
            && !(MIN_PROXY_UPSTREAMS_FILE_REFRESH_SECS..=MAX_PROXY_UPSTREAMS_FILE_REFRESH_SECS)
                .contains(&self.upstreams_file_refresh_secs)
        {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstreams_file_refresh_secs",
                reason: "must be between 1 and 300 seconds",
            });
        }
        if let Some(url) = &self.upstreams_http_url {
            #[cfg(not(feature = "load-balancer"))]
            {
                let _ = url;
                return Err(ConfigError::InvalidProxyUpstreamPolicy {
                    field: "proxy.upstreams_http_url",
                    reason: "requires the load-balancer feature",
                });
            }
            #[cfg(feature = "load-balancer")]
            {
                if !valid_http_endpoint_url(url) {
                    return Err(ConfigError::InvalidProxyUpstreamPolicy {
                        field: "proxy.upstreams_http_url",
                        reason: "must be an http:// or https:// endpoint URL without credentials, query, or fragment",
                    });
                }
                if let Some(rest) = url.strip_prefix("http://") {
                    let authority = rest.split('/').next().unwrap_or_default();
                    if !http_authority_is_numeric_loopback(authority) {
                        return Err(ConfigError::InvalidProxyUpstreamPolicy {
                            field: "proxy.upstreams_http_url",
                            reason: "must use https:// unless the endpoint is numeric loopback http://",
                        });
                    }
                }
                if !(MIN_PROXY_UPSTREAMS_FILE_REFRESH_SECS..=MAX_PROXY_UPSTREAMS_FILE_REFRESH_SECS)
                    .contains(&self.upstreams_http_refresh_secs)
                {
                    return Err(ConfigError::InvalidProxyUpstreamPolicy {
                        field: "proxy.upstreams_http_refresh_secs",
                        reason: "must be between 1 and 300 seconds",
                    });
                }
                if let Some(path) = &self.upstreams_http_bearer_token_file {
                    validate_path("proxy.upstreams_http_bearer_token_file", Some(path))?;
                    validate_non_world_writable_parent(
                        "proxy.upstreams_http_bearer_token_file",
                        Some(path),
                    )?;
                }
                if !self.upstream_weights.is_empty()
                    || !self.upstream_priority_groups.is_empty()
                    || self.upstream_priority_group_min_active
                        != default_upstream_priority_group_min_active()
                    || !self.upstream_localities.is_empty()
                    || !self.preferred_upstream_localities.is_empty()
                    || !self.upstream_max_in_flight.is_empty()
                    || !self.upstream_aliases.is_empty()
                    || !self.upstream_tags.is_empty()
                    || !self.backup_upstreams.is_empty()
                    || !self.drain_upstreams.is_empty()
                    || !self.disabled_upstreams.is_empty()
                {
                    return Err(ConfigError::InvalidProxyUpstreamPolicy {
                        field: "proxy.upstreams_http_url",
                        reason: "cannot be combined with upstream_weights, upstream_priority_groups, upstream_priority_group_min_active, upstream_localities, preferred_upstream_localities, upstream_max_in_flight, upstream_aliases, upstream_tags, backup_upstreams, drain_upstreams, or disabled_upstreams in this release",
                    });
                }
                if self.upstream_tls && self.upstream_sni.is_none() {
                    return Err(ConfigError::InvalidProxyTlsPolicy {
                        reason: "upstreams_http_url with upstream_tls requires explicit upstream_sni",
                    });
                }
            }
        } else if self.upstreams_http_bearer_token_file.is_some() {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstreams_http_bearer_token_file",
                reason: "requires proxy.upstreams_http_url",
            });
        }
        if let Some(refresh_secs) = self.upstream_dns_refresh_secs {
            #[cfg(not(feature = "load-balancer"))]
            {
                let _ = refresh_secs;
                return Err(ConfigError::InvalidProxyUpstreamPolicy {
                    field: "proxy.upstream_dns_refresh_secs",
                    reason: "requires the load-balancer feature",
                });
            }
            #[cfg(feature = "load-balancer")]
            {
                if !(MIN_PROXY_UPSTREAM_DNS_REFRESH_SECS..=MAX_PROXY_UPSTREAM_DNS_REFRESH_SECS)
                    .contains(&refresh_secs)
                {
                    return Err(ConfigError::InvalidProxyUpstreamPolicy {
                        field: "proxy.upstream_dns_refresh_secs",
                        reason: "must be between 1 and 300 seconds",
                    });
                }
                if self.upstream.is_some()
                    || self.upstreams.is_empty()
                    || self.upstreams_file.is_some()
                    || self.upstreams_http_url.is_some()
                {
                    return Err(ConfigError::InvalidProxyUpstreamPolicy {
                        field: "proxy.upstream_dns_refresh_secs",
                        reason: "requires proxy.upstreams and cannot be used with proxy.upstream, proxy.upstreams_file, or proxy.upstreams_http_url",
                    });
                }
                if !self.upstream_weights.is_empty()
                    || !self.upstream_priority_groups.is_empty()
                    || self.upstream_priority_group_min_active
                        != default_upstream_priority_group_min_active()
                    || !self.upstream_localities.is_empty()
                    || !self.preferred_upstream_localities.is_empty()
                    || !self.upstream_max_in_flight.is_empty()
                    || !self.upstream_aliases.is_empty()
                    || !self.upstream_tags.is_empty()
                    || !self.backup_upstreams.is_empty()
                    || !self.drain_upstreams.is_empty()
                    || !self.disabled_upstreams.is_empty()
                {
                    return Err(ConfigError::InvalidProxyUpstreamPolicy {
                        field: "proxy.upstream_dns_refresh_secs",
                        reason: "cannot be combined with upstream_weights, upstream_priority_groups, upstream_priority_group_min_active, upstream_localities, preferred_upstream_localities, upstream_max_in_flight, upstream_aliases, upstream_tags, backup_upstreams, drain_upstreams, or disabled_upstreams in this release",
                    });
                }
            }
        } else if self.upstream_dns_allow_private_backends {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstream_dns_allow_private_backends",
                reason: "requires proxy.upstream_dns_refresh_secs",
            });
        }
        if self.upstreams.len() > MAX_PROXY_UPSTREAMS {
            return Err(ConfigError::TooManyProxyUpstreams {
                max: MAX_PROXY_UPSTREAMS,
            });
        }
        if !self.upstream_weights.is_empty() {
            if self.upstream.is_some() || self.upstream_weights.len() != self.upstreams.len() {
                return Err(ConfigError::InvalidProxyUpstreamWeights {
                    reason: "upstream_weights must match proxy.upstreams and cannot be used with proxy.upstream",
                });
            }
            let mut total_weight = 0usize;
            for weight in &self.upstream_weights {
                if *weight == 0 {
                    return Err(ConfigError::InvalidProxyUpstreamWeights {
                        reason: "weights must be greater than zero",
                    });
                }
                if *weight > MAX_PROXY_UPSTREAM_WEIGHT {
                    return Err(ConfigError::InvalidProxyUpstreamWeights {
                        reason: "each weight must be at most 1000",
                    });
                }
                total_weight = total_weight.saturating_add(*weight);
            }
            if total_weight > MAX_PROXY_UPSTREAM_TOTAL_WEIGHT {
                return Err(ConfigError::InvalidProxyUpstreamWeights {
                    reason: "total upstream weight is too large",
                });
            }
        }
        if !self.upstream_priority_groups.is_empty() {
            if self.upstream.is_some()
                || self.upstream_priority_groups.len() != self.upstreams.len()
            {
                return Err(ConfigError::InvalidProxyUpstreamPolicy {
                    field: "proxy.upstream_priority_groups",
                    reason: "upstream_priority_groups must match proxy.upstreams and cannot be used with proxy.upstream",
                });
            }
            if self.upstream_priority_group_min_active == 0
                || self.upstream_priority_group_min_active > self.upstreams.len()
            {
                return Err(ConfigError::InvalidProxyUpstreamPolicy {
                    field: "proxy.upstream_priority_group_min_active",
                    reason: "priority group activation threshold must be between 1 and the number of upstreams",
                });
            }
            for priority in &self.upstream_priority_groups {
                if *priority > MAX_PROXY_UPSTREAM_PRIORITY_GROUP {
                    return Err(ConfigError::InvalidProxyUpstreamPolicy {
                        field: "proxy.upstream_priority_groups",
                        reason: "priority groups must be at most 1000",
                    });
                }
            }
        }
        if self.upstream_priority_groups.is_empty()
            && self.upstream_priority_group_min_active
                != default_upstream_priority_group_min_active()
        {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstream_priority_group_min_active",
                reason: "requires proxy.upstream_priority_groups",
            });
        }
        if !self.upstream_localities.is_empty() {
            if self.upstream.is_some() || self.upstream_localities.len() != self.upstreams.len() {
                return Err(ConfigError::InvalidProxyUpstreamPolicy {
                    field: "proxy.upstream_localities",
                    reason: "upstream_localities must match proxy.upstreams and cannot be used with proxy.upstream",
                });
            }
            let mut configured_localities = std::collections::HashSet::new();
            for locality in &self.upstream_localities {
                if !valid_upstream_alias(locality) {
                    return Err(ConfigError::InvalidProxyUpstreamPolicy {
                        field: "proxy.upstream_localities",
                        reason: "localities must be 1-64 ASCII letters, digits, dots, dashes, or underscores",
                    });
                }
                configured_localities.insert(locality.to_ascii_lowercase());
            }
            let mut seen_preferred = std::collections::HashSet::new();
            for locality in &self.preferred_upstream_localities {
                if !valid_upstream_alias(locality) {
                    return Err(ConfigError::InvalidProxyUpstreamPolicy {
                        field: "proxy.preferred_upstream_localities",
                        reason: "preferred localities must be 1-64 ASCII letters, digits, dots, dashes, or underscores",
                    });
                }
                let normalized = locality.to_ascii_lowercase();
                if !configured_localities.contains(&normalized) {
                    return Err(ConfigError::InvalidProxyUpstreamPolicy {
                        field: "proxy.preferred_upstream_localities",
                        reason: "preferred localities must be present in proxy.upstream_localities",
                    });
                }
                if !seen_preferred.insert(normalized) {
                    return Err(ConfigError::InvalidProxyUpstreamPolicy {
                        field: "proxy.preferred_upstream_localities",
                        reason: "preferred localities must be unique case-insensitively",
                    });
                }
            }
        } else if !self.preferred_upstream_localities.is_empty() {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.preferred_upstream_localities",
                reason: "requires proxy.upstream_localities",
            });
        }
        if !self.upstream_max_in_flight.is_empty() {
            if self.upstream.is_some() || self.upstream_max_in_flight.len() != self.upstreams.len()
            {
                return Err(ConfigError::InvalidProxyUpstreamPolicy {
                    field: "proxy.upstream_max_in_flight",
                    reason: "upstream_max_in_flight must match proxy.upstreams and cannot be used with proxy.upstream",
                });
            }
            for max_in_flight in &self.upstream_max_in_flight {
                if *max_in_flight == 0 || *max_in_flight > MAX_PROXY_UPSTREAM_MAX_IN_FLIGHT {
                    return Err(ConfigError::InvalidProxyUpstreamPolicy {
                        field: "proxy.upstream_max_in_flight",
                        reason: "max in-flight values must be between 1 and 1000000",
                    });
                }
            }
        }
        if !self.upstream_aliases.is_empty() {
            if self.upstream.is_some() || self.upstream_aliases.len() != self.upstreams.len() {
                return Err(ConfigError::InvalidProxyUpstreamPolicy {
                    field: "proxy.upstream_aliases",
                    reason: "upstream_aliases must match proxy.upstreams and cannot be used with proxy.upstream",
                });
            }
            let mut seen_aliases = std::collections::HashSet::new();
            for alias in &self.upstream_aliases {
                if !valid_upstream_alias(alias) {
                    return Err(ConfigError::InvalidProxyUpstreamPolicy {
                        field: "proxy.upstream_aliases",
                        reason: "aliases must be 1-64 ASCII letters, digits, dots, dashes, or underscores",
                    });
                }
                if !seen_aliases.insert(alias.to_ascii_lowercase()) {
                    return Err(ConfigError::InvalidProxyUpstreamPolicy {
                        field: "proxy.upstream_aliases",
                        reason: "aliases must be unique case-insensitively",
                    });
                }
            }
        }
        if !self.upstream_tags.is_empty() {
            if self.upstream.is_some() || self.upstream_tags.len() != self.upstreams.len() {
                return Err(ConfigError::InvalidProxyUpstreamPolicy {
                    field: "proxy.upstream_tags",
                    reason: "upstream_tags must match proxy.upstreams and cannot be used with proxy.upstream",
                });
            }
            for tags in &self.upstream_tags {
                if tags.len() > MAX_PROXY_UPSTREAM_TAGS_PER_BACKEND {
                    return Err(ConfigError::InvalidProxyUpstreamPolicy {
                        field: "proxy.upstream_tags",
                        reason: "each upstream may have at most 16 tags",
                    });
                }
                let mut seen_tags = std::collections::HashSet::new();
                for tag in tags {
                    if !valid_upstream_alias(tag) {
                        return Err(ConfigError::InvalidProxyUpstreamPolicy {
                            field: "proxy.upstream_tags",
                            reason: "tags must be 1-64 ASCII letters, digits, dots, dashes, or underscores",
                        });
                    }
                    if !seen_tags.insert(tag.to_ascii_lowercase()) {
                        return Err(ConfigError::InvalidProxyUpstreamPolicy {
                            field: "proxy.upstream_tags",
                            reason: "tags must be unique per upstream case-insensitively",
                        });
                    }
                }
            }
        }
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
        self.validate_upstream_policy()?;

        if let Some(sni) = &self.upstream_sni
            && sni.trim().is_empty()
        {
            return Err(ConfigError::EmptyUpstreamSni);
        }
        if self.upstream_tls
            && self.upstream_verify_cert
            && self.upstream_sni.is_none()
            && self.static_upstreams_include_ip_address()
        {
            return Err(ConfigError::InvalidProxyTlsPolicy {
                reason: "IP-addressed upstreams with upstream_tls and upstream_verify_cert require explicit upstream_sni",
            });
        }
        if !self.upstream_verify_cert && self.upstream_verify_hostname {
            return Err(ConfigError::InvalidProxyTlsPolicy {
                reason: "upstream_verify_hostname must be false when upstream_verify_cert = false",
            });
        }
        if !self.upstream_tls
            && (self.upstream_ca_path.is_some()
                || self.upstream_client_cert_path.is_some()
                || self.upstream_client_key_path.is_some())
        {
            return Err(ConfigError::InvalidProxyTlsPolicy {
                reason: "upstream TLS trust roots or client certificates require upstream_tls = true",
            });
        }
        if !self.upstream_verify_cert && self.upstream_ca_path.is_some() {
            return Err(ConfigError::InvalidProxyTlsPolicy {
                reason: "upstream_ca_path requires upstream_verify_cert = true",
            });
        }
        match (
            &self.upstream_client_cert_path,
            &self.upstream_client_key_path,
        ) {
            (Some(_), Some(_)) | (None, None) => {}
            _ => {
                return Err(ConfigError::InvalidProxyTlsPolicy {
                    reason: "upstream_client_cert_path and upstream_client_key_path must be configured together",
                });
            }
        }
        for (field, path) in [
            ("proxy.upstream_ca_path", self.upstream_ca_path.as_deref()),
            (
                "proxy.upstream_client_cert_path",
                self.upstream_client_cert_path.as_deref(),
            ),
            (
                "proxy.upstream_client_key_path",
                self.upstream_client_key_path.as_deref(),
            ),
        ] {
            validate_path(field, path)?;
            validate_non_world_writable_parent(field, path)?;
        }
        if self.upstream_proxy_protocol != UpstreamProxyProtocol::Off
            && !self.has_configured_upstream()
        {
            return Err(ConfigError::InvalidProxyTlsPolicy {
                reason: "upstream_proxy_protocol requires a configured proxy upstream",
            });
        }
        if self.upstream_http_version != UpstreamHttpVersion::Http1
            && !self.has_configured_upstream()
        {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstream_http_version",
                reason: "requires a configured proxy upstream",
            });
        }
        if self.upstream_h2c_upgrade {
            if !self.has_configured_upstream() {
                return Err(ConfigError::InvalidProxyUpstreamPolicy {
                    field: "proxy.upstream_h2c_upgrade",
                    reason: "requires a configured proxy upstream",
                });
            }
            if self.upstream_tls {
                return Err(ConfigError::InvalidProxyUpstreamPolicy {
                    field: "proxy.upstream_h2c_upgrade",
                    reason: "is only valid for plaintext upstreams",
                });
            }
            if self.upstream_http_version != UpstreamHttpVersion::Http1AndHttp2 {
                return Err(ConfigError::InvalidProxyUpstreamPolicy {
                    field: "proxy.upstream_h2c_upgrade",
                    reason: "requires upstream_http_version = \"http1-and-http2\"",
                });
            }
        }
        if self.websocket && self.upstream_http_version != UpstreamHttpVersion::Http1 {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.websocket",
                reason: "HTTP/1.1 upgrade proxying requires upstream_http_version = \"http1\"",
            });
        }
        self.auth_request.validate("proxy.auth_request")?;
        self.mirror.validate("proxy.mirror")?;
        if self.upstream_h2_max_streams.is_some()
            && self.upstream_http_version == UpstreamHttpVersion::Http1
        {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstream_h2_max_streams",
                reason: "requires upstream_http_version to allow http2",
            });
        }
        if self.upstream_h2_ping_interval_secs.is_some()
            && self.upstream_http_version == UpstreamHttpVersion::Http1
        {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstream_h2_ping_interval_secs",
                reason: "requires upstream_http_version to allow http2",
            });
        }
        if self
            .upstream_h2_max_streams
            .is_some_and(|streams| streams == 0 || streams > MAX_PROXY_UPSTREAM_H2_STREAMS)
        {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstream_h2_max_streams",
                reason: "must be between 1 and 1024",
            });
        }
        if let Some(alternative_cn) = &self.upstream_alternative_cn {
            if alternative_cn.contains('*') {
                return Err(ConfigError::InvalidProxyTlsPolicy {
                    reason: "upstream_alternative_cn must not contain wildcards",
                });
            }
            if normalize_host(alternative_cn).is_none() {
                return Err(ConfigError::InvalidProxyTlsPolicy {
                    reason: "upstream_alternative_cn must be a valid hostname",
                });
            }
        }

        validate_optional_timeout_secs("proxy.connect_timeout_secs", self.connect_timeout_secs)?;
        validate_optional_timeout_secs(
            "proxy.upstream_total_connection_timeout_secs",
            self.upstream_total_connection_timeout_secs,
        )?;
        validate_optional_timeout_secs(
            "proxy.upstream_idle_timeout_secs",
            self.upstream_idle_timeout_secs,
        )?;
        validate_optional_timeout_secs(
            "proxy.upstream_tcp_keepalive_idle_secs",
            self.upstream_tcp_keepalive_idle_secs,
        )?;
        validate_optional_timeout_secs(
            "proxy.upstream_tcp_keepalive_interval_secs",
            self.upstream_tcp_keepalive_interval_secs,
        )?;
        if self.upstream_tcp_keepalive_count.is_some()
            || self.upstream_tcp_keepalive_idle_secs.is_some()
            || self.upstream_tcp_keepalive_interval_secs.is_some()
            || self.upstream_tcp_user_timeout_ms.is_some()
        {
            match (
                self.upstream_tcp_keepalive_idle_secs,
                self.upstream_tcp_keepalive_interval_secs,
                self.upstream_tcp_keepalive_count,
            ) {
                (Some(_), Some(_), Some(count))
                    if (1..=MAX_PROXY_UPSTREAM_TCP_KEEPALIVE_COUNT).contains(&count) => {}
                _ => {
                    return Err(ConfigError::InvalidProxyUpstreamPolicy {
                        field: "proxy.upstream_tcp_keepalive_count",
                        reason: "TCP keepalive requires idle_secs, interval_secs, and count, with count between 1 and 128",
                    });
                }
            }
        }
        if self
            .upstream_tcp_user_timeout_ms
            .is_some_and(|milliseconds| milliseconds == 0)
        {
            return Err(ConfigError::InvalidProxyTimeout {
                field: "proxy.upstream_tcp_user_timeout_ms",
            });
        }
        if self.upstream_tcp_recv_buffer_bytes.is_some_and(|bytes| {
            bytes.as_u64() == 0 || bytes.as_u64() > MAX_PROXY_UPSTREAM_TCP_RECV_BUFFER_BYTES
        }) {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstream_tcp_recv_buffer_bytes",
                reason: "must be between 1 byte and 256MiB",
            });
        }
        if self
            .upstream_dscp
            .is_some_and(|dscp| dscp > MAX_PROXY_UPSTREAM_DSCP)
        {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstream_dscp",
                reason: "must be a DSCP value between 0 and 63",
            });
        }
        validate_optional_timeout_secs("proxy.read_timeout_secs", self.read_timeout_secs)?;
        validate_optional_timeout_secs("proxy.send_timeout_secs", self.send_timeout_secs)?;
        validate_optional_timeout_secs(
            "proxy.upstream_h2_ping_interval_secs",
            self.upstream_h2_ping_interval_secs,
        )?;
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
        if self.load_balance.selection.uses_maglev()
            && (self.upstreams_file.is_some()
                || self.upstreams_http_url.is_some()
                || self.upstream_dns_refresh_secs.is_some())
        {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "maglev selections require a static proxy.upstreams pool; file, HTTP, and DNS discovery pools rebuild membership dynamically",
            });
        }
        Ok(())
    }

    fn static_upstreams_include_ip_address(&self) -> bool {
        let mut upstreams = self.upstreams.iter().map(String::as_str);
        if let Some(upstream) = self.upstream.as_deref() {
            return upstream_authority_host_is_ip(upstream);
        }
        if self.upstreams.is_empty()
            && self.upstreams_file.is_none()
            && self.upstreams_http_url.is_none()
        {
            return upstream_authority_host_is_ip(DEFAULT_UPSTREAM);
        }
        upstreams.any(upstream_authority_host_is_ip)
    }

    fn validate_upstream_policy(&self) -> Result<(), ConfigError> {
        if self.backup_upstreams.is_empty()
            && self.drain_upstreams.is_empty()
            && self.disabled_upstreams.is_empty()
        {
            return Ok(());
        }
        if self.upstreams.len() < 2 || self.upstream.is_some() {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstreams",
                reason: "backup_upstreams, drain_upstreams, and disabled_upstreams require proxy.upstreams with at least two entries",
            });
        }
        let configured = self
            .upstreams
            .iter()
            .map(|upstream| upstream.to_ascii_lowercase())
            .collect::<HashSet<_>>();
        let backup = validate_proxy_upstream_subset(
            "proxy.backup_upstreams",
            &self.backup_upstreams,
            &configured,
        )?;
        let drain = validate_proxy_upstream_subset(
            "proxy.drain_upstreams",
            &self.drain_upstreams,
            &configured,
        )?;
        let disabled = validate_proxy_upstream_subset(
            "proxy.disabled_upstreams",
            &self.disabled_upstreams,
            &configured,
        )?;
        if !backup.is_disjoint(&drain)
            || !backup.is_disjoint(&disabled)
            || !drain.is_disjoint(&disabled)
        {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.backup_upstreams",
                reason: "backup_upstreams, drain_upstreams, and disabled_upstreams must not overlap",
            });
        }
        let primary_count = configured
            .len()
            .saturating_sub(backup.len() + drain.len() + disabled.len());
        if primary_count == 0 {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstreams",
                reason: "at least one upstream must remain primary and selectable",
            });
        }
        Ok(())
    }
}

impl ProxyConfigFragment {
    pub(crate) fn has_conflicting_upstream_sources(&self) -> bool {
        usize::from(self.upstream.is_some())
            + usize::from(
                self.upstreams
                    .as_ref()
                    .is_some_and(|upstreams| !upstreams.is_empty()),
            )
            + usize::from(self.upstreams_file.is_some())
            + usize::from(self.upstreams_http_url.is_some())
            > 1
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
        if let Some(load_balance) = &mut self.load_balance {
            load_balance.resolve_relative_paths(base_dir);
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
        if let Some(error_pages) = &mut self.error_pages {
            for error_page in error_pages {
                error_page.resolve_relative_paths(base_dir);
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthRequestConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub url: Option<String>,
    #[serde(default)]
    pub forward_headers: Vec<String>,
    #[serde(default)]
    pub allow_response_headers: Vec<String>,
    #[serde(default = "default_auth_request_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_auth_request_read_timeout_secs")]
    pub read_timeout_secs: u64,
    #[serde(default = "default_auth_request_max_response_bytes")]
    pub max_response_bytes: ByteSize,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthRequestConfigFragment {
    enabled: Option<bool>,
    url: Option<String>,
    forward_headers: Option<Vec<String>>,
    allow_response_headers: Option<Vec<String>>,
    connect_timeout_secs: Option<u64>,
    read_timeout_secs: Option<u64>,
    max_response_bytes: Option<ByteSize>,
}

impl Default for AuthRequestConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            url: None,
            forward_headers: Vec::new(),
            allow_response_headers: Vec::new(),
            connect_timeout_secs: default_auth_request_connect_timeout_secs(),
            read_timeout_secs: default_auth_request_read_timeout_secs(),
            max_response_bytes: default_auth_request_max_response_bytes(),
        }
    }
}

impl AuthRequestConfig {
    fn merge(&mut self, fragment: AuthRequestConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(url) = fragment.url {
            self.url = Some(url);
        }
        if let Some(headers) = fragment.forward_headers {
            self.forward_headers = headers;
        }
        if let Some(headers) = fragment.allow_response_headers {
            self.allow_response_headers = headers;
        }
        if let Some(timeout) = fragment.connect_timeout_secs {
            self.connect_timeout_secs = timeout;
        }
        if let Some(timeout) = fragment.read_timeout_secs {
            self.read_timeout_secs = timeout;
        }
        if let Some(bytes) = fragment.max_response_bytes {
            self.max_response_bytes = bytes;
        }
    }

    fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        let Some(url) = self.url.as_deref() else {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: scope,
                reason: "enabled auth_request requires url",
            });
        };
        if !valid_http_endpoint_url(url) {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: scope,
                reason: "url must be an absolute http:// or https:// URL without userinfo, query, fragment, control characters, or an empty path",
            });
        }
        validate_config_list_len(
            format!("{scope}.forward_headers"),
            self.forward_headers.len(),
            MAX_AUTH_REQUEST_HEADERS,
        )?;
        validate_config_list_len(
            format!("{scope}.allow_response_headers"),
            self.allow_response_headers.len(),
            MAX_AUTH_REQUEST_HEADERS,
        )?;
        let mut seen = BTreeSet::new();
        for header in &self.forward_headers {
            validate_header_name(scope, header)?;
            if !seen.insert(header.to_ascii_lowercase()) {
                return Err(ConfigError::InvalidProxyUpstreamPolicy {
                    field: scope,
                    reason: "forward_headers contains duplicate header names",
                });
            }
        }
        seen.clear();
        for header in &self.allow_response_headers {
            validate_header_name(scope, header)?;
            if !seen.insert(header.to_ascii_lowercase()) {
                return Err(ConfigError::InvalidProxyUpstreamPolicy {
                    field: scope,
                    reason: "allow_response_headers contains duplicate header names",
                });
            }
        }
        validate_required_timeout_secs(
            "proxy.auth_request.connect_timeout_secs",
            self.connect_timeout_secs,
        )?;
        validate_required_timeout_secs(
            "proxy.auth_request.read_timeout_secs",
            self.read_timeout_secs,
        )?;
        if self.max_response_bytes.as_u64() == 0
            || self.max_response_bytes.as_u64() > MAX_AUTH_REQUEST_RESPONSE_BYTES
        {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: scope,
                reason: "max_response_bytes must be between 1 byte and 1 MiB",
            });
        }
        Ok(())
    }
}

const MAX_AUTH_REQUEST_HEADERS: usize = 32;
const MAX_AUTH_REQUEST_RESPONSE_BYTES: u64 = 1024 * 1024;

fn default_auth_request_connect_timeout_secs() -> u64 {
    2
}

fn default_auth_request_read_timeout_secs() -> u64 {
    5
}

fn default_auth_request_max_response_bytes() -> ByteSize {
    ByteSize::from_bytes(64 * 1024)
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficMirrorConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub base_url: Option<String>,
    #[serde(default = "default_traffic_mirror_sample_per_mille")]
    pub sample_per_mille: u16,
    #[serde(default = "default_traffic_mirror_methods")]
    pub methods: Vec<String>,
    #[serde(default)]
    pub forward_headers: Vec<String>,
    #[serde(default = "default_traffic_mirror_timeout_secs")]
    pub timeout_secs: u64,
    #[serde(default = "default_traffic_mirror_max_response_bytes")]
    pub max_response_bytes: ByteSize,
    #[serde(default = "default_traffic_mirror_max_in_flight")]
    pub max_in_flight: usize,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficMirrorConfigFragment {
    enabled: Option<bool>,
    base_url: Option<String>,
    sample_per_mille: Option<u16>,
    methods: Option<Vec<String>>,
    forward_headers: Option<Vec<String>>,
    timeout_secs: Option<u64>,
    max_response_bytes: Option<ByteSize>,
    max_in_flight: Option<usize>,
}

impl Default for TrafficMirrorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            base_url: None,
            sample_per_mille: default_traffic_mirror_sample_per_mille(),
            methods: default_traffic_mirror_methods(),
            forward_headers: Vec::new(),
            timeout_secs: default_traffic_mirror_timeout_secs(),
            max_response_bytes: default_traffic_mirror_max_response_bytes(),
            max_in_flight: default_traffic_mirror_max_in_flight(),
        }
    }
}

impl TrafficMirrorConfig {
    fn merge(&mut self, fragment: TrafficMirrorConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(base_url) = fragment.base_url {
            self.base_url = Some(base_url);
        }
        if let Some(sample) = fragment.sample_per_mille {
            self.sample_per_mille = sample;
        }
        if let Some(methods) = fragment.methods {
            self.methods = methods;
        }
        if let Some(headers) = fragment.forward_headers {
            self.forward_headers = headers;
        }
        if let Some(timeout) = fragment.timeout_secs {
            self.timeout_secs = timeout;
        }
        if let Some(bytes) = fragment.max_response_bytes {
            self.max_response_bytes = bytes;
        }
        if let Some(max_in_flight) = fragment.max_in_flight {
            self.max_in_flight = max_in_flight;
        }
    }

    fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if !cfg!(feature = "traffic-mirror") {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: scope,
                reason: "traffic mirroring requires building Fluxheim with the traffic-mirror feature",
            });
        }
        if cfg!(feature = "privacy-mode") {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: scope,
                reason: "traffic mirroring is not available in privacy-mode builds",
            });
        }
        let Some(base_url) = self.base_url.as_deref() else {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: scope,
                reason: "enabled traffic mirroring requires base_url",
            });
        };
        if !valid_http_base_url(base_url) {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: scope,
                reason: "base_url must be an absolute http:// or https:// URL without userinfo, query, fragment, or control characters",
            });
        }
        if self.sample_per_mille == 0 || self.sample_per_mille > 1000 {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: scope,
                reason: "sample_per_mille must be between 1 and 1000",
            });
        }
        validate_config_list_len(
            format!("{scope}.methods"),
            self.methods.len(),
            MAX_TRAFFIC_MIRROR_METHODS,
        )?;
        let mut seen = BTreeSet::new();
        for method in &self.methods {
            if method.is_empty()
                || method.len() > 32
                || !method
                    .bytes()
                    .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'-')
            {
                return Err(ConfigError::InvalidProxyUpstreamPolicy {
                    field: scope,
                    reason: "methods must be uppercase HTTP method tokens",
                });
            }
            if !seen.insert(method.clone()) {
                return Err(ConfigError::InvalidProxyUpstreamPolicy {
                    field: scope,
                    reason: "methods contains duplicate method names",
                });
            }
            if !LB_SAFE_RETRY_METHODS.iter().any(|safe| safe == method) {
                return Err(ConfigError::InvalidProxyUpstreamPolicy {
                    field: scope,
                    reason: "traffic mirroring only allows safe methods GET, HEAD, OPTIONS, and TRACE in this release",
                });
            }
        }
        validate_config_list_len(
            format!("{scope}.forward_headers"),
            self.forward_headers.len(),
            MAX_TRAFFIC_MIRROR_HEADERS,
        )?;
        seen.clear();
        for header in &self.forward_headers {
            validate_header_name(scope, header)?;
            if !seen.insert(header.to_ascii_lowercase()) {
                return Err(ConfigError::InvalidProxyUpstreamPolicy {
                    field: scope,
                    reason: "forward_headers contains duplicate header names",
                });
            }
        }
        validate_required_timeout_secs("proxy.mirror.timeout_secs", self.timeout_secs)?;
        if self.max_response_bytes.as_u64() == 0
            || self.max_response_bytes.as_u64() > MAX_TRAFFIC_MIRROR_RESPONSE_BYTES
        {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: scope,
                reason: "max_response_bytes must be between 1 byte and 1 MiB",
            });
        }
        if self.max_in_flight == 0 || self.max_in_flight > MAX_TRAFFIC_MIRROR_IN_FLIGHT {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: scope,
                reason: "max_in_flight must be between 1 and 1024",
            });
        }
        Ok(())
    }
}

const MAX_TRAFFIC_MIRROR_METHODS: usize = 16;
const MAX_TRAFFIC_MIRROR_HEADERS: usize = 32;
const MAX_TRAFFIC_MIRROR_RESPONSE_BYTES: u64 = 1024 * 1024;
const MAX_TRAFFIC_MIRROR_IN_FLIGHT: usize = 1024;

fn default_traffic_mirror_sample_per_mille() -> u16 {
    1000
}

fn default_traffic_mirror_methods() -> Vec<String> {
    vec!["GET".to_owned(), "HEAD".to_owned(), "OPTIONS".to_owned()]
}

fn default_traffic_mirror_timeout_secs() -> u64 {
    2
}

fn default_traffic_mirror_max_response_bytes() -> ByteSize {
    ByteSize::from_bytes(16 * 1024)
}

fn default_traffic_mirror_max_in_flight() -> usize {
    64
}

fn validate_proxy_upstream_subset(
    field: &'static str,
    values: &[String],
    configured: &HashSet<String>,
) -> Result<HashSet<String>, ConfigError> {
    let mut seen = HashSet::new();
    for upstream in values {
        if !valid_authority(upstream) {
            return Err(ConfigError::InvalidUpstream {
                address: upstream.clone(),
            });
        }
        let normalized = upstream.to_ascii_lowercase();
        if !configured.contains(&normalized) {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field,
                reason: "each entry must also be present in proxy.upstreams",
            });
        }
        if !seen.insert(normalized) {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field,
                reason: "duplicate upstream policy entries are not allowed",
            });
        }
    }
    Ok(seen)
}

fn upstream_authority_host_is_ip(upstream: &str) -> bool {
    upstream_host(upstream).is_some_and(|host| host.parse::<IpAddr>().is_ok())
}

#[cfg(feature = "load-balancer")]
fn validate_load_balancer_backend_keys(upstreams: &[String]) -> Result<(), ConfigError> {
    let mut seen = HashSet::new();
    for upstream in upstreams {
        let normalized = upstream.to_ascii_lowercase();
        if !seen.insert(backend_authority_key(&normalized)) {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: "proxy.upstreams",
                reason: "load-balancer backend key collision detected; use distinct upstream addresses",
            });
        }
    }
    Ok(())
}

#[cfg(feature = "load-balancer")]
fn backend_authority_key(authority: &str) -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

    struct Fnv1a64(u64);

    impl Hasher for Fnv1a64 {
        fn finish(&self) -> u64 {
            self.0
        }

        fn write(&mut self, bytes: &[u8]) {
            for byte in bytes {
                self.0 ^= u64::from(*byte);
                self.0 = self.0.wrapping_mul(FNV_PRIME);
            }
        }
    }

    let mut hasher = Fnv1a64(FNV_OFFSET);
    hasher.write(authority.as_bytes());
    hasher.finish()
}

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

    fn validate(&self) -> Result<(), ConfigError> {
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
fn default_proxy_upstreams_file_refresh_secs() -> u64 {
    5
}

fn default_proxy_upstreams_http_refresh_secs() -> u64 {
    5
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

fn default_upstream_priority_group_min_active() -> usize {
    1
}

#[cfg(all(test, feature = "load-balancer"))]
mod tests {
    use super::*;

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
