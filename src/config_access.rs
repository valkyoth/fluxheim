use std::collections::BTreeSet;

use crate::config::{ConfigError, validate_config_list_len};
use crate::config_net::valid_ip_matcher;

const MAX_ACCESS_RULES: usize = 256;

pub(crate) fn validate_access_rule_list(
    scope: &'static str,
    field: &'static str,
    values: &[String],
) -> Result<(), ConfigError> {
    validate_config_list_len(format!("{scope}.{field}"), values.len(), MAX_ACCESS_RULES)?;

    let mut seen = BTreeSet::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed != value || !valid_ip_matcher(trimmed) {
            return Err(ConfigError::InvalidAccessRule {
                field: access_rule_field(scope, field),
                value: value.clone(),
            });
        }
        if !seen.insert(trimmed.to_ascii_lowercase()) {
            return Err(ConfigError::DuplicateAccessRule {
                field: access_rule_field(scope, field),
                value: value.clone(),
            });
        }
    }

    Ok(())
}

pub(crate) fn validate_client_cert_sha256_list(
    scope: &'static str,
    field: &'static str,
    values: &[String],
) -> Result<(), ConfigError> {
    validate_config_list_len(format!("{scope}.{field}"), values.len(), MAX_ACCESS_RULES)?;

    let mut seen = BTreeSet::new();
    for value in values {
        let trimmed = value.trim();
        if trimmed != value || !valid_sha256_hex(trimmed) {
            return Err(ConfigError::InvalidAccessRule {
                field: access_rule_field(scope, field),
                value: value.clone(),
            });
        }
        if !seen.insert(trimmed.to_ascii_lowercase()) {
            return Err(ConfigError::DuplicateAccessRule {
                field: access_rule_field(scope, field),
                value: value.clone(),
            });
        }
    }

    Ok(())
}

fn access_rule_field(scope: &'static str, field: &'static str) -> &'static str {
    match (scope, field) {
        ("vhosts.access", "allow") => "vhosts.access.allow",
        ("vhosts.access", "deny") => "vhosts.access.deny",
        ("vhosts.access", "allow_client_cert_sha256") => "vhosts.access.allow_client_cert_sha256",
        ("vhosts.access", "deny_client_cert_sha256") => "vhosts.access.deny_client_cert_sha256",
        ("vhosts.routes.access", "allow") => "vhosts.routes.access.allow",
        ("vhosts.routes.access", "deny") => "vhosts.routes.access.deny",
        ("vhosts.routes.access", "allow_client_cert_sha256") => {
            "vhosts.routes.access.allow_client_cert_sha256"
        }
        ("vhosts.routes.access", "deny_client_cert_sha256") => {
            "vhosts.routes.access.deny_client_cert_sha256"
        }
        ("admin.client_certificate", "allow_sha256") => "admin.client_certificate.allow_sha256",
        ("admin.client_certificate", "deny_sha256") => "admin.client_certificate.deny_sha256",
        _ => "access",
    }
}

fn valid_sha256_hex(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}
