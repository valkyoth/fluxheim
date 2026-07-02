use crate::config::ConfigError;
use crate::config_header::valid_http_header_name;
use crate::config_path::{validate_non_world_writable_parent, validate_path};

use super::{
    LoadBalanceConfig, LoadBalanceConfigFragment, LoadBalancePersistenceMode, LoadBalanceSelection,
    MAX_BOUNDED_LOAD_FACTOR_PER_MILLE, MIN_BOUNDED_LOAD_FACTOR_PER_MILLE,
    default_bounded_load_factor_per_mille,
};

impl LoadBalanceConfig {
    pub fn merge(&mut self, fragment: LoadBalanceConfigFragment) {
        if let Some(selection) = fragment.selection {
            self.selection = selection;
        }
        if let Some(header) = fragment.hash_header {
            self.hash_header = Some(header);
        }
        if let Some(cookie) = fragment.hash_cookie {
            self.hash_cookie = Some(cookie);
        }
        if let Some(max_iterations) = fragment.max_iterations {
            self.max_iterations = max_iterations;
        }
        if let Some(status) = fragment.all_down_status {
            self.all_down_status = status;
        }
        if let Some(factor) = fragment.bounded_load_factor_per_mille {
            self.bounded_load_factor_per_mille = factor;
        }
        if let Some(health_check) = fragment.health_check {
            self.health_check.merge(health_check);
        }
        if let Some(passive_health) = fragment.passive_health {
            self.passive_health.merge(passive_health);
        }
        if let Some(slow_start) = fragment.slow_start {
            self.slow_start.merge(slow_start);
        }
        if let Some(retry) = fragment.retry {
            self.retry.merge(retry);
        }
        if let Some(persistence) = fragment.persistence {
            self.persistence.merge(persistence);
        }
        if let Some(path) = fragment.runtime_state_file {
            self.runtime_state_file = Some(path);
        }
        if let Some(queue) = fragment.queue {
            self.queue.merge(queue);
        }
    }

    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.selection.requires_hash_header() {
            let Some(header) = self.hash_header.as_deref() else {
                return Err(ConfigError::InvalidLoadBalanceSelection {
                    reason: "header-hash selections require proxy.load_balance.hash_header",
                });
            };
            if !valid_http_header_name(header) {
                return Err(ConfigError::InvalidHeaderName {
                    field: "proxy.load_balance.hash_header",
                    name: header.to_owned(),
                });
            }
        } else if self.hash_header.is_some() {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.hash_header can only be used with header-hash selections",
            });
        }
        if self.selection.requires_hash_cookie() {
            let Some(cookie) = self.hash_cookie.as_deref() else {
                return Err(ConfigError::InvalidLoadBalanceSelection {
                    reason: "cookie-hash selections require proxy.load_balance.hash_cookie",
                });
            };
            if !valid_http_header_name(cookie) {
                return Err(ConfigError::InvalidLoadBalanceSelection {
                    reason: "proxy.load_balance.hash_cookie must be a valid cookie name",
                });
            }
        } else if self.hash_cookie.is_some() {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.hash_cookie can only be used with cookie-hash selections",
            });
        }
        if self.max_iterations == 0 {
            return Err(ConfigError::InvalidLoadBalanceMaxIterations);
        }
        if self.selection == LoadBalanceSelection::LeastSessions && !self.persistence.enabled {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "least-sessions selection requires proxy.load_balance.persistence.enabled = true",
            });
        }
        if !(500..=599).contains(&self.all_down_status) {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.all_down_status must be an HTTP 5xx status",
            });
        }
        if !(MIN_BOUNDED_LOAD_FACTOR_PER_MILLE..=MAX_BOUNDED_LOAD_FACTOR_PER_MILLE)
            .contains(&self.bounded_load_factor_per_mille)
        {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.bounded_load_factor_per_mille must be between 1000 and 10000",
            });
        }
        if self.bounded_load_factor_per_mille != default_bounded_load_factor_per_mille()
            && !self.selection.uses_bounded_load()
        {
            return Err(ConfigError::InvalidLoadBalanceSelection {
                reason: "proxy.load_balance.bounded_load_factor_per_mille can only be used with bounded-load consistent-hash selections",
            });
        }

        self.health_check.validate()?;
        self.passive_health.validate()?;
        self.slow_start.validate()?;
        self.retry.validate()?;
        self.persistence.validate()?;
        if let Some(path) = &self.runtime_state_file {
            validate_path("proxy.load_balance.runtime_state_file", Some(path))?;
            validate_non_world_writable_parent(
                "proxy.load_balance.runtime_state_file",
                Some(path),
            )?;
            if self.persistence.enabled
                && matches!(
                    self.persistence.mode,
                    LoadBalancePersistenceMode::Header | LoadBalancePersistenceMode::Cookie
                )
            {
                let persistence_mode = match self.persistence.mode {
                    LoadBalancePersistenceMode::Header => "header",
                    LoadBalancePersistenceMode::Cookie => "cookie",
                    LoadBalancePersistenceMode::SourceIp => "source-ip",
                    LoadBalancePersistenceMode::ManagedCookie => "managed-cookie",
                };
                log::warn!(
                    target: "fluxheim::security",
                    "proxy.load_balance.runtime_state_file is configured with raw {} persistence; client affinity identifiers are written to disk at {}. Use managed-cookie mode or an encrypted, access-restricted volume for session-bearing identifiers.",
                    persistence_mode,
                    path.display()
                );
            }
        }
        self.queue.validate()?;
        Ok(())
    }
}
