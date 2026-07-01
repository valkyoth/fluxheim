use std::collections::BTreeSet;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::config::{ByteSize, ConfigError};
use crate::config_net::http_authority_is_loopback;
use crate::config_path::{validate_non_world_writable_parent, validate_path};

const CACHE_PEER_FILL_MAX_PEERS: usize = 32;
const CACHE_PEER_FILL_MAX_CONCURRENT_REQUESTS: usize = 1024;

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CachePeerFillConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub peers: Vec<CachePeerConfig>,
    #[serde(default = "default_cache_peer_fill_connect_timeout_secs")]
    pub connect_timeout_secs: u64,
    #[serde(default = "default_cache_peer_fill_read_timeout_secs")]
    pub read_timeout_secs: u64,
    #[serde(default)]
    pub max_object_bytes: Option<ByteSize>,
    #[serde(default = "default_cache_peer_fill_max_concurrent_requests")]
    pub max_concurrent_requests: usize,
    #[serde(default)]
    pub allow_insecure_http: bool,
    #[serde(default)]
    pub shared_secret_file: Option<PathBuf>,
    #[serde(default = "default_true")]
    pub fail_open: bool,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CachePeerFillConfigFragment {
    enabled: Option<bool>,
    peers: Option<Vec<CachePeerConfig>>,
    connect_timeout_secs: Option<u64>,
    read_timeout_secs: Option<u64>,
    max_object_bytes: Option<ByteSize>,
    max_concurrent_requests: Option<usize>,
    allow_insecure_http: Option<bool>,
    shared_secret_file: Option<PathBuf>,
    fail_open: Option<bool>,
}

impl Default for CachePeerFillConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            peers: Vec::new(),
            connect_timeout_secs: default_cache_peer_fill_connect_timeout_secs(),
            read_timeout_secs: default_cache_peer_fill_read_timeout_secs(),
            max_object_bytes: None,
            max_concurrent_requests: default_cache_peer_fill_max_concurrent_requests(),
            allow_insecure_http: false,
            shared_secret_file: None,
            fail_open: true,
        }
    }
}

impl CachePeerFillConfig {
    pub(crate) fn merge(&mut self, fragment: CachePeerFillConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(peers) = fragment.peers {
            self.peers = peers;
        }
        if let Some(timeout_secs) = fragment.connect_timeout_secs {
            self.connect_timeout_secs = timeout_secs;
        }
        if let Some(timeout_secs) = fragment.read_timeout_secs {
            self.read_timeout_secs = timeout_secs;
        }
        if let Some(max_object_bytes) = fragment.max_object_bytes {
            self.max_object_bytes = Some(max_object_bytes);
        }
        if let Some(max_concurrent_requests) = fragment.max_concurrent_requests {
            self.max_concurrent_requests = max_concurrent_requests;
        }
        if let Some(allow_insecure_http) = fragment.allow_insecure_http {
            self.allow_insecure_http = allow_insecure_http;
        }
        if let Some(shared_secret_file) = fragment.shared_secret_file {
            self.shared_secret_file = Some(shared_secret_file);
        }
        if let Some(fail_open) = fragment.fail_open {
            self.fail_open = fail_open;
        }
    }

    pub(crate) fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(path) = &mut self.shared_secret_file
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
    }

    pub(crate) fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
        #[cfg(not(feature = "cache"))]
        if self.enabled {
            return Err(ConfigError::CachePeerFillNotCompiled);
        }

        if !self.enabled {
            return Ok(());
        }

        if self.peers.is_empty() || self.peers.len() > CACHE_PEER_FILL_MAX_PEERS {
            return Err(ConfigError::InvalidCachePeerFillPolicy {
                scope,
                field: "peer_fill.peers",
                reason: "peer fill requires between 1 and 32 peers",
            });
        }
        if self.connect_timeout_secs == 0 || self.connect_timeout_secs > 300 {
            return Err(ConfigError::InvalidCachePeerFillPolicy {
                scope,
                field: "peer_fill.connect_timeout_secs",
                reason: "connect timeout must be between 1 and 300 seconds",
            });
        }
        if self.read_timeout_secs == 0 || self.read_timeout_secs > 3600 {
            return Err(ConfigError::InvalidCachePeerFillPolicy {
                scope,
                field: "peer_fill.read_timeout_secs",
                reason: "read timeout must be between 1 and 3600 seconds",
            });
        }
        if self.max_object_bytes.is_some_and(|size| size.as_u64() == 0) {
            return Err(ConfigError::InvalidCachePeerFillPolicy {
                scope,
                field: "peer_fill.max_object_bytes",
                reason: "max object bytes must be greater than zero",
            });
        }
        if self.max_concurrent_requests == 0
            || self.max_concurrent_requests > CACHE_PEER_FILL_MAX_CONCURRENT_REQUESTS
        {
            return Err(ConfigError::InvalidCachePeerFillPolicy {
                scope,
                field: "peer_fill.max_concurrent_requests",
                reason: "max concurrent requests must be between 1 and 1024",
            });
        }
        let shared_secret_file_field = format!("{scope}.peer_fill.shared_secret_file");
        validate_path(
            shared_secret_file_field.clone(),
            self.shared_secret_file.as_deref(),
        )?;
        validate_non_world_writable_parent(
            shared_secret_file_field,
            self.shared_secret_file.as_deref(),
        )?;

        let mut seen_names = BTreeSet::new();
        let mut seen_urls = BTreeSet::new();
        for peer in &self.peers {
            peer.validate(scope, self.allow_insecure_http)?;
            if self.shared_secret_file.is_none()
                && cache_peer_base_url_is_non_loopback_http(&peer.base_url)
            {
                return Err(ConfigError::InvalidCachePeerFillPeer {
                    scope,
                    peer: peer.name.clone(),
                    reason: "non-loopback http peer base_url requires peer_fill.shared_secret_file",
                });
            }
            if !seen_names.insert(peer.name.to_ascii_lowercase()) {
                return Err(ConfigError::DuplicateCachePeerFillPeerName {
                    scope,
                    name: peer.name.clone(),
                });
            }
            if !seen_urls.insert(peer.base_url.trim_end_matches('/').to_ascii_lowercase()) {
                return Err(ConfigError::DuplicateCachePeerFillPeerUrl {
                    scope,
                    url: peer.base_url.clone(),
                });
            }
        }

        Ok(())
    }
}

impl CachePeerFillConfigFragment {
    pub(crate) fn resolve_relative_paths(&mut self, base_dir: &Path) {
        if let Some(path) = &mut self.shared_secret_file
            && path.is_relative()
        {
            *path = base_dir.join(&path);
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CachePeerConfig {
    pub name: String,
    pub base_url: String,
}

impl CachePeerConfig {
    fn validate(&self, scope: &'static str, allow_insecure_http: bool) -> Result<(), ConfigError> {
        validate_cache_peer_name(scope, &self.name)?;
        validate_cache_peer_base_url(scope, &self.name, &self.base_url, allow_insecure_http)
    }
}

fn default_cache_peer_fill_connect_timeout_secs() -> u64 {
    2
}

fn default_cache_peer_fill_read_timeout_secs() -> u64 {
    10
}

fn default_cache_peer_fill_max_concurrent_requests() -> usize {
    64
}

fn default_true() -> bool {
    true
}

fn validate_cache_peer_name(scope: &'static str, name: &str) -> Result<(), ConfigError> {
    if name.is_empty()
        || name.len() > 64
        || name
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    {
        return Err(ConfigError::InvalidCachePeerFillPeer {
            scope,
            peer: name.to_owned(),
            reason: "peer name must be 1-64 ASCII letters, digits, dots, dashes, or underscores",
        });
    }
    Ok(())
}

fn validate_cache_peer_base_url(
    scope: &'static str,
    peer: &str,
    base_url: &str,
    allow_insecure_http: bool,
) -> Result<(), ConfigError> {
    let base_url = base_url.trim();
    let Some((scheme, rest)) = base_url.split_once("://") else {
        return Err(ConfigError::InvalidCachePeerFillPeer {
            scope,
            peer: peer.to_owned(),
            reason: "peer base_url must start with https:// or http://",
        });
    };
    if !matches!(scheme, "https" | "http")
        || rest.is_empty()
        || base_url.len() > 2048
        || base_url.chars().any(char::is_whitespace)
        || base_url.chars().any(char::is_control)
        || base_url.contains('?')
        || base_url.contains('#')
    {
        return Err(ConfigError::InvalidCachePeerFillPeer {
            scope,
            peer: peer.to_owned(),
            reason: "peer base_url must be a safe HTTP(S) origin URL without query or fragment",
        });
    }

    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    if authority.contains('@') || !valid_cache_peer_authority(authority) {
        return Err(ConfigError::InvalidCachePeerFillPeer {
            scope,
            peer: peer.to_owned(),
            reason: "peer base_url authority must be a valid host:port or ip:port without userinfo",
        });
    }
    if !path.is_empty() && path != "/" {
        return Err(ConfigError::InvalidCachePeerFillPeer {
            scope,
            peer: peer.to_owned(),
            reason: "peer base_url must not include a path yet",
        });
    }
    if scheme == "http" && !allow_insecure_http && !cache_peer_authority_is_loopback(authority) {
        return Err(ConfigError::InvalidCachePeerFillPeer {
            scope,
            peer: peer.to_owned(),
            reason: "http peer base_url is allowed only for loopback peers unless allow_insecure_http = true",
        });
    }

    Ok(())
}

fn cache_peer_base_url_is_non_loopback_http(base_url: &str) -> bool {
    let Some(rest) = base_url.trim().strip_prefix("http://") else {
        return false;
    };
    let (authority, _) = rest.split_once('/').unwrap_or((rest, ""));
    !cache_peer_authority_is_loopback(authority)
}

fn valid_cache_peer_authority(authority: &str) -> bool {
    if authority.starts_with('[') {
        let Some(end) = authority.find(']') else {
            return false;
        };
        let host = &authority[1..end];
        let tail = &authority[end + 1..];
        return !host.is_empty()
            && host.parse::<IpAddr>().is_ok()
            && tail
                .strip_prefix(':')
                .is_some_and(|port| port.parse::<u16>().is_ok_and(|port| port != 0));
    }

    let Some((host, port)) = authority.rsplit_once(':') else {
        return false;
    };
    port.parse::<u16>().is_ok_and(|port| port != 0)
        && (host.parse::<IpAddr>().is_ok() || valid_cache_peer_hostname(host))
}

fn valid_cache_peer_hostname(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 253
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn cache_peer_authority_is_loopback(authority: &str) -> bool {
    http_authority_is_loopback(authority)
}
