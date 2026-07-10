use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use crate::config::{
    ByteSize, ConfigError, validate_config_list_len, validate_required_timeout_secs,
};
use crate::config_header::validate_header_name;
use crate::config_http::valid_http_endpoint_url;

const MAX_AUTH_REQUEST_HEADERS: usize = 32;
const MAX_AUTH_REQUEST_RESPONSE_BYTES: u64 = 1024 * 1024;
const MAX_AUTH_REQUEST_IN_FLIGHT: usize = 100_000;

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
    #[serde(default = "default_auth_request_max_in_flight")]
    pub max_in_flight: usize,
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
    max_in_flight: Option<usize>,
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
            max_in_flight: default_auth_request_max_in_flight(),
        }
    }
}

impl AuthRequestConfig {
    pub(crate) fn merge(&mut self, fragment: AuthRequestConfigFragment) {
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
        if let Some(max_in_flight) = fragment.max_in_flight {
            self.max_in_flight = max_in_flight;
        }
    }

    pub(crate) fn validate(&self, scope: &'static str) -> Result<(), ConfigError> {
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
        if self.max_in_flight == 0 || self.max_in_flight > MAX_AUTH_REQUEST_IN_FLIGHT {
            return Err(ConfigError::InvalidProxyUpstreamPolicy {
                field: scope,
                reason: "max_in_flight must be between 1 and 100000",
            });
        }
        Ok(())
    }
}

fn default_auth_request_connect_timeout_secs() -> u64 {
    2
}

fn default_auth_request_read_timeout_secs() -> u64 {
    5
}

fn default_auth_request_max_response_bytes() -> ByteSize {
    ByteSize::from_bytes(64 * 1024)
}

const fn default_auth_request_max_in_flight() -> usize {
    64
}
