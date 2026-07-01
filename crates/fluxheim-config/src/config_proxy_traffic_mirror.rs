use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::config::{
    ByteSize, ConfigError, validate_config_list_len, validate_required_timeout_secs,
};
use crate::config_header::validate_header_name;
use crate::config_http::valid_http_base_url;
use crate::config_load_balance::LB_SAFE_RETRY_METHODS;

const MAX_TRAFFIC_MIRROR_METHODS: usize = 16;
const MAX_TRAFFIC_MIRROR_HEADERS: usize = 32;
const MAX_TRAFFIC_MIRROR_RESPONSE_BYTES: u64 = 1024 * 1024;
const MAX_TRAFFIC_MIRROR_IN_FLIGHT: usize = 1024;

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
    pub(crate) fn merge(&mut self, fragment: TrafficMirrorConfigFragment) {
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

    pub(crate) fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
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
