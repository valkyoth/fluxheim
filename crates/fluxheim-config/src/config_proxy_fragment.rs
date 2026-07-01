use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::ByteSize;
use crate::config_load_balance::LoadBalanceConfigFragment;
use crate::config_proxy_auth::AuthRequestConfigFragment;
use crate::config_proxy_error_page::ProxyErrorPageConfig;
use crate::config_proxy_protocol::{UpstreamHttpVersion, UpstreamProxyProtocol};
use crate::config_proxy_traffic_mirror::TrafficMirrorConfigFragment;

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyConfigFragment {
    pub(crate) upstream: Option<String>,
    pub(crate) upstreams: Option<Vec<String>>,
    pub(crate) upstreams_file: Option<PathBuf>,
    pub(crate) upstreams_file_refresh_secs: Option<u64>,
    pub(crate) upstreams_http_url: Option<String>,
    pub(crate) upstreams_http_refresh_secs: Option<u64>,
    pub(crate) upstreams_http_bearer_token_file: Option<PathBuf>,
    pub(crate) upstreams_http_allow_private_backends: Option<bool>,
    pub(crate) upstream_dns_refresh_secs: Option<u64>,
    pub(crate) upstream_dns_allow_private_backends: Option<bool>,
    pub(crate) upstream_weights: Option<Vec<usize>>,
    pub(crate) upstream_priority_groups: Option<Vec<u16>>,
    pub(crate) upstream_priority_group_min_active: Option<usize>,
    pub(crate) upstream_localities: Option<Vec<String>>,
    pub(crate) preferred_upstream_localities: Option<Vec<String>>,
    pub(crate) upstream_max_in_flight: Option<Vec<usize>>,
    pub(crate) upstream_aliases: Option<Vec<String>>,
    pub(crate) upstream_tags: Option<Vec<Vec<String>>>,
    pub(crate) backup_upstreams: Option<Vec<String>>,
    pub(crate) drain_upstreams: Option<Vec<String>>,
    pub(crate) disabled_upstreams: Option<Vec<String>>,
    pub(crate) upstream_tls: Option<bool>,
    pub(crate) upstream_sni: Option<String>,
    pub(crate) upstream_verify_cert: Option<bool>,
    pub(crate) upstream_verify_hostname: Option<bool>,
    pub(crate) upstream_alternative_cn: Option<String>,
    pub(crate) upstream_ca_path: Option<PathBuf>,
    pub(crate) upstream_client_cert_path: Option<PathBuf>,
    pub(crate) upstream_client_key_path: Option<PathBuf>,
    pub(crate) upstream_proxy_protocol: Option<UpstreamProxyProtocol>,
    pub(crate) upstream_http_version: Option<UpstreamHttpVersion>,
    pub(crate) upstream_h2c_upgrade: Option<bool>,
    pub(crate) websocket: Option<bool>,
    pub(crate) auth_request: Option<AuthRequestConfigFragment>,
    pub(crate) mirror: Option<TrafficMirrorConfigFragment>,
    pub(crate) upstream_h2_max_streams: Option<usize>,
    pub(crate) upstream_h2_ping_interval_secs: Option<u64>,
    pub(crate) connect_timeout_secs: Option<u64>,
    pub(crate) upstream_total_connection_timeout_secs: Option<u64>,
    pub(crate) upstream_idle_timeout_secs: Option<u64>,
    pub(crate) upstream_tcp_keepalive_idle_secs: Option<u64>,
    pub(crate) upstream_tcp_keepalive_interval_secs: Option<u64>,
    pub(crate) upstream_tcp_keepalive_count: Option<usize>,
    pub(crate) upstream_tcp_user_timeout_ms: Option<u64>,
    pub(crate) upstream_tcp_recv_buffer_bytes: Option<ByteSize>,
    pub(crate) upstream_dscp: Option<u8>,
    pub(crate) upstream_tcp_fast_open: Option<bool>,
    pub(crate) read_timeout_secs: Option<u64>,
    pub(crate) send_timeout_secs: Option<u64>,
    pub(crate) downstream_read_timeout_secs: Option<u64>,
    pub(crate) downstream_write_timeout_secs: Option<u64>,
    pub(crate) downstream_total_response_timeout_secs: Option<u64>,
    pub(crate) downstream_min_send_rate_bytes_per_sec: Option<usize>,
    pub(crate) error_pages: Option<Vec<ProxyErrorPageConfig>>,
    pub(crate) load_balance: Option<LoadBalanceConfigFragment>,
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
