use std::path::Path;

use crate::config::ConfigError;
use crate::config_net::upstream_host;
use crate::config_proxy::{DEFAULT_UPSTREAM, ProxyConfig, ProxyConfigFragment};
use crate::config_proxy_validate::validate_proxy_config;

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
        validate_proxy_config(self, DEFAULT_UPSTREAM)
    }
}
