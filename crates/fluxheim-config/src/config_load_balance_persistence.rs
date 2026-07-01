use serde::{Deserialize, Serialize};

use crate::config::ConfigError;
use crate::config_header::valid_http_header_name;

const MAX_LB_PERSISTENCE_TTL_SECS: u64 = 86_400;
const MAX_LB_PERSISTENCE_TABLE_ENTRIES: usize = 1_000_000;

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoadBalancePersistenceMode {
    #[default]
    SourceIp,
    Header,
    Cookie,
    ManagedCookie,
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum LoadBalanceManagedCookieSameSite {
    Strict,
    #[default]
    Lax,
    None,
}

#[cfg(feature = "load-balancer")]
impl LoadBalanceManagedCookieSameSite {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Strict => "Strict",
            Self::Lax => "Lax",
            Self::None => "None",
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalancePersistenceConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub mode: LoadBalancePersistenceMode,
    #[serde(default)]
    pub header: Option<String>,
    #[serde(default)]
    pub cookie: Option<String>,
    #[serde(default = "default_lb_persistence_ttl_secs")]
    pub ttl_secs: u64,
    #[serde(default = "default_lb_persistence_table_max_entries")]
    pub table_max_entries: usize,
    #[serde(default)]
    pub managed_cookie_domain: Option<String>,
    #[serde(default)]
    pub managed_cookie_path: Option<String>,
    #[serde(default = "default_lb_managed_cookie_secure")]
    pub managed_cookie_secure: bool,
    #[serde(default = "default_lb_managed_cookie_http_only")]
    pub managed_cookie_http_only: bool,
    #[serde(default)]
    pub managed_cookie_same_site: LoadBalanceManagedCookieSameSite,
    #[serde(default)]
    pub managed_cookie_max_age_secs: Option<u64>,
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LoadBalancePersistenceConfigFragment {
    enabled: Option<bool>,
    mode: Option<LoadBalancePersistenceMode>,
    header: Option<String>,
    cookie: Option<String>,
    ttl_secs: Option<u64>,
    table_max_entries: Option<usize>,
    managed_cookie_domain: Option<String>,
    managed_cookie_path: Option<String>,
    managed_cookie_secure: Option<bool>,
    managed_cookie_http_only: Option<bool>,
    managed_cookie_same_site: Option<LoadBalanceManagedCookieSameSite>,
    managed_cookie_max_age_secs: Option<u64>,
}

impl Default for LoadBalancePersistenceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            mode: LoadBalancePersistenceMode::default(),
            header: None,
            cookie: None,
            ttl_secs: default_lb_persistence_ttl_secs(),
            table_max_entries: default_lb_persistence_table_max_entries(),
            managed_cookie_domain: None,
            managed_cookie_path: None,
            managed_cookie_secure: default_lb_managed_cookie_secure(),
            managed_cookie_http_only: default_lb_managed_cookie_http_only(),
            managed_cookie_same_site: LoadBalanceManagedCookieSameSite::default(),
            managed_cookie_max_age_secs: None,
        }
    }
}

impl LoadBalancePersistenceConfig {
    pub(crate) fn merge(&mut self, fragment: LoadBalancePersistenceConfigFragment) {
        if let Some(enabled) = fragment.enabled {
            self.enabled = enabled;
        }
        if let Some(mode) = fragment.mode {
            self.mode = mode;
        }
        if let Some(header) = fragment.header {
            self.header = Some(header);
        }
        if let Some(cookie) = fragment.cookie {
            self.cookie = Some(cookie);
        }
        if let Some(ttl_secs) = fragment.ttl_secs {
            self.ttl_secs = ttl_secs;
        }
        if let Some(entries) = fragment.table_max_entries {
            self.table_max_entries = entries;
        }
        if let Some(domain) = fragment.managed_cookie_domain {
            self.managed_cookie_domain = Some(domain);
        }
        if let Some(path) = fragment.managed_cookie_path {
            self.managed_cookie_path = Some(path);
        }
        if let Some(secure) = fragment.managed_cookie_secure {
            self.managed_cookie_secure = secure;
        }
        if let Some(http_only) = fragment.managed_cookie_http_only {
            self.managed_cookie_http_only = http_only;
        }
        if let Some(same_site) = fragment.managed_cookie_same_site {
            self.managed_cookie_same_site = same_site;
        }
        if let Some(max_age) = fragment.managed_cookie_max_age_secs {
            self.managed_cookie_max_age_secs = Some(max_age);
        }
    }

    pub(crate) fn validate(&self) -> Result<(), ConfigError> {
        #[cfg(feature = "privacy-mode")]
        if self.enabled {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.persistence is not available in privacy-mode builds",
            });
        }

        if self.ttl_secs == 0 || self.ttl_secs > MAX_LB_PERSISTENCE_TTL_SECS {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.persistence.ttl_secs must be between 1 and 86400",
            });
        }
        if self.table_max_entries == 0 || self.table_max_entries > MAX_LB_PERSISTENCE_TABLE_ENTRIES
        {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.persistence.table_max_entries must be between 1 and 1000000",
            });
        }
        if self.mode != LoadBalancePersistenceMode::Header && self.header.is_some() {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.persistence.header can only be used with mode = \"header\"",
            });
        }
        if !matches!(
            self.mode,
            LoadBalancePersistenceMode::Cookie | LoadBalancePersistenceMode::ManagedCookie
        ) && self.cookie.is_some()
        {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.persistence.cookie can only be used with mode = \"cookie\" or \"managed-cookie\"",
            });
        }
        match self.mode {
            LoadBalancePersistenceMode::SourceIp => {}
            LoadBalancePersistenceMode::Header => {
                let Some(header) = self.header.as_deref() else {
                    return Err(ConfigError::InvalidLoadBalanceSelection {
                        reason: "proxy.load_balance.persistence.header is required when mode = \"header\"",
                    });
                };
                if !valid_http_header_name(header) {
                    return Err(ConfigError::InvalidHeaderName {
                        field: "proxy.load_balance.persistence.header",
                        name: header.to_owned(),
                    });
                }
            }
            LoadBalancePersistenceMode::Cookie | LoadBalancePersistenceMode::ManagedCookie => {
                let Some(cookie) = self.cookie.as_deref() else {
                    return Err(ConfigError::InvalidLoadBalanceSelection {
                        reason: "proxy.load_balance.persistence.cookie is required when mode = \"cookie\" or \"managed-cookie\"",
                    });
                };
                if !valid_http_header_name(cookie) {
                    return Err(ConfigError::InvalidLoadBalanceSelection {
                        reason: "proxy.load_balance.persistence.cookie must be a valid cookie name",
                    });
                }
            }
        }
        if self.mode != LoadBalancePersistenceMode::ManagedCookie {
            if self.managed_cookie_domain.is_some()
                || self.managed_cookie_path.is_some()
                || self.managed_cookie_max_age_secs.is_some()
                || !self.managed_cookie_secure
                || !self.managed_cookie_http_only
                || self.managed_cookie_same_site != LoadBalanceManagedCookieSameSite::default()
            {
                return Err(ConfigError::InvalidLoadBalanceSelection {
                    reason: "proxy.load_balance.persistence managed_cookie_* fields can only be used with mode = \"managed-cookie\"",
                });
            }
        } else {
            validate_managed_cookie_attributes(self)?;
        }
        Ok(())
    }
}

fn default_lb_persistence_ttl_secs() -> u64 {
    300
}

fn default_lb_persistence_table_max_entries() -> usize {
    65_536
}

fn default_lb_managed_cookie_secure() -> bool {
    true
}

fn default_lb_managed_cookie_http_only() -> bool {
    true
}

fn validate_managed_cookie_attributes(
    config: &LoadBalancePersistenceConfig,
) -> Result<(), ConfigError> {
    if let Some(path) = config.managed_cookie_path.as_deref()
        && (!path.starts_with('/')
            || !path.is_ascii()
            || path.len() > 256
            || path
                .bytes()
                .any(|byte| byte.is_ascii_control() || matches!(byte, b';' | b',')))
    {
        return Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence.managed_cookie_path must be an absolute ASCII cookie path without controls, ';', or ','",
        });
    }
    if let Some(domain) = config.managed_cookie_domain.as_deref()
        && (domain.is_empty()
            || !domain.is_ascii()
            || domain.len() > 253
            || domain
                .bytes()
                .any(|byte| byte.is_ascii_control() || matches!(byte, b';' | b',')))
    {
        return Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence.managed_cookie_domain must be a non-empty ASCII cookie domain without controls, ';', or ','",
        });
    }
    if let Some(max_age) = config.managed_cookie_max_age_secs
        && (max_age == 0 || max_age > MAX_LB_PERSISTENCE_TTL_SECS)
    {
        return Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence.managed_cookie_max_age_secs must be between 1 and 86400",
        });
    }
    if config.managed_cookie_same_site == LoadBalanceManagedCookieSameSite::None
        && !config.managed_cookie_secure
    {
        return Err(ConfigError::InvalidLoadBalanceSelection {
            reason: "proxy.load_balance.persistence.managed_cookie_same_site = \"none\" requires managed_cookie_secure = true",
        });
    }
    Ok(())
}
