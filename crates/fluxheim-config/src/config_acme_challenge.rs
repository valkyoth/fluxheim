use serde::{Deserialize, Serialize};

use crate::config::{
    AccessPolicyConfig, ConcurrencyLimitConfig, ConfigError, GrpcRouteConfig, ProxyConfig,
    RateLimitConfig, RouteConfig, VhostHeaderPolicyConfig, validate_optional_timeout_secs,
};
use crate::config_net::valid_authority;

pub const MAX_ACME_CHALLENGE_UPSTREAMS: usize = 64;

const ACME_HTTP_CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VhostAcmeChallengeConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub upstream: Option<String>,
    #[serde(default)]
    pub upstreams: Vec<String>,
    #[serde(default)]
    pub upstream_tls: bool,
    #[serde(default)]
    pub connect_timeout_secs: Option<u64>,
    #[serde(default)]
    pub read_timeout_secs: Option<u64>,
    #[serde(default)]
    pub send_timeout_secs: Option<u64>,
}

impl VhostAcmeChallengeConfig {
    pub fn validate(&self, vhost: &str) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }

        if self.upstream.is_some() && !self.upstreams.is_empty() {
            return Err(ConfigError::ConflictingAcmeChallengeUpstreams {
                vhost: vhost.to_owned(),
            });
        }
        if self.upstream.is_none() && self.upstreams.is_empty() {
            return Err(ConfigError::MissingAcmeChallengeUpstream {
                vhost: vhost.to_owned(),
            });
        }
        if self.upstreams.len() > MAX_ACME_CHALLENGE_UPSTREAMS {
            return Err(ConfigError::TooManyAcmeChallengeUpstreams {
                vhost: vhost.to_owned(),
                max: MAX_ACME_CHALLENGE_UPSTREAMS,
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
                return Err(ConfigError::DuplicateAcmeChallengeUpstream {
                    vhost: vhost.to_owned(),
                    upstream: upstream.clone(),
                });
            }
        }

        validate_optional_timeout_secs(
            "vhosts.acme_challenge.connect_timeout_secs",
            self.connect_timeout_secs,
        )?;
        validate_optional_timeout_secs(
            "vhosts.acme_challenge.read_timeout_secs",
            self.read_timeout_secs,
        )?;
        validate_optional_timeout_secs(
            "vhosts.acme_challenge.send_timeout_secs",
            self.send_timeout_secs,
        )?;
        Ok(())
    }

    pub fn route_config(&self) -> Option<RouteConfig> {
        self.enabled.then(|| RouteConfig {
            name: "acme-http-01".to_owned(),
            path_exact: None,
            path_prefix: Some(ACME_HTTP_CHALLENGE_PREFIX.to_owned()),
            path_regex: None,
            methods: Vec::new(),
            fallback: false,
            https_redirect_exempt: true,
            strip_prefix: None,
            rewrite_prefix: None,
            rewrite_template: None,
            max_request_body_bytes: None,
            access: AccessPolicyConfig::default(),
            rate_limit: RateLimitConfig::default(),
            concurrency: ConcurrencyLimitConfig::default(),
            grpc: GrpcRouteConfig::default(),
            redirect: None,
            proxy: Some(ProxyConfig {
                upstream: self.upstream.clone(),
                upstreams: self.upstreams.clone(),
                upstream_tls: self.upstream_tls,
                connect_timeout_secs: self.connect_timeout_secs,
                read_timeout_secs: self.read_timeout_secs,
                send_timeout_secs: self.send_timeout_secs,
                ..ProxyConfig::default()
            }),
            web: None,
            php: None,
            cache: None,
            compression: None,
            headers: VhostHeaderPolicyConfig::default(),
        })
    }
}
