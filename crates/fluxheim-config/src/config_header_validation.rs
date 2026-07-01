use std::collections::BTreeMap;

use crate::config::{
    ConfigError, MAX_ROUTE_REGEX_CAPTURE_NAME_BYTES, MAX_ROUTE_REGEX_CAPTURE_VALUES,
};
use crate::config_header::{
    HeaderValues, MAX_HEADER_APPEND_VALUES, MAX_HEADER_MUTATION_NAMES,
    MAX_RESPONSE_HEADER_REWRITE_RULES, ResponseHeaderRewriteRuleConfig,
};

pub fn validate_optional_header_value(
    field: &'static str,
    value: Option<&str>,
) -> Result<(), ConfigError> {
    let Some(value) = value else {
        return Ok(());
    };

    if value.trim().is_empty() || header_value_contains_disallowed_control(value) {
        return Err(ConfigError::InvalidResponseHeaderValue { field });
    }

    Ok(())
}

pub fn validate_header_mutations(
    field: &'static str,
    unset: &[String],
    set: &BTreeMap<String, String>,
    append: &BTreeMap<String, HeaderValues>,
) -> Result<(), ConfigError> {
    validate_header_mutation_len(field, "unset", unset.len(), MAX_HEADER_MUTATION_NAMES)?;
    validate_header_mutation_len(field, "set", set.len(), MAX_HEADER_MUTATION_NAMES)?;
    validate_header_mutation_len(field, "append", append.len(), MAX_HEADER_MUTATION_NAMES)?;

    for name in unset {
        validate_header_name(field, name)?;
    }
    for (name, value) in set {
        validate_header_name(field, name)?;
        validate_header_mutation_value(field, name, value)?;
    }
    for (name, values) in append {
        validate_header_name(field, name)?;
        validate_header_mutation_len(
            field,
            "append values",
            values.len(),
            MAX_HEADER_APPEND_VALUES,
        )?;
        for value in values.iter() {
            validate_header_mutation_value(field, name, value)?;
        }
    }

    Ok(())
}

pub fn validate_no_tls_header_append(
    field: &'static str,
    append: &BTreeMap<String, HeaderValues>,
) -> Result<(), ConfigError> {
    for (name, values) in append {
        if values.iter().any(header_value_uses_tls_template) {
            return Err(ConfigError::UnsafeTlsHeaderAppend {
                field,
                name: name.clone(),
            });
        }
    }
    Ok(())
}

pub fn validate_response_header_rewrite_rules(
    field: &'static str,
    header: &'static str,
    rules: &[ResponseHeaderRewriteRuleConfig],
) -> Result<(), ConfigError> {
    validate_header_mutation_len(
        field,
        header,
        rules.len(),
        MAX_RESPONSE_HEADER_REWRITE_RULES,
    )?;

    let mut seen = std::collections::BTreeSet::new();
    for rule in rules {
        validate_response_header_rewrite_endpoint(field, header, "from", &rule.from)?;
        validate_response_header_rewrite_endpoint(field, header, "to", &rule.to)?;
        if !seen.insert(rule.from.as_str()) {
            return Err(ConfigError::ConflictingHeaderAdd {
                field,
                name: format!("{header}.from"),
            });
        }
    }

    Ok(())
}

pub fn validate_cookie_domain_rewrite_rules(
    field: &'static str,
    rules: &[ResponseHeaderRewriteRuleConfig],
) -> Result<(), ConfigError> {
    validate_header_mutation_len(
        field,
        "cookie_domain",
        rules.len(),
        MAX_RESPONSE_HEADER_REWRITE_RULES,
    )?;

    let mut seen = std::collections::BTreeSet::new();
    for rule in rules {
        validate_cookie_domain_rewrite_endpoint(field, "from", &rule.from)?;
        validate_cookie_domain_rewrite_endpoint(field, "to", &rule.to)?;
        if !seen.insert(rule.from.to_ascii_lowercase()) {
            return Err(ConfigError::ConflictingHeaderAdd {
                field,
                name: "cookie_domain.from".to_owned(),
            });
        }
    }

    Ok(())
}

pub fn validate_cookie_path_rewrite_rules(
    field: &'static str,
    rules: &[ResponseHeaderRewriteRuleConfig],
) -> Result<(), ConfigError> {
    validate_header_mutation_len(
        field,
        "cookie_path",
        rules.len(),
        MAX_RESPONSE_HEADER_REWRITE_RULES,
    )?;

    let mut seen = std::collections::BTreeSet::new();
    for rule in rules {
        validate_cookie_path_rewrite_endpoint(field, "from", &rule.from)?;
        validate_cookie_path_rewrite_endpoint(field, "to", &rule.to)?;
        if !seen.insert(rule.from.as_str()) {
            return Err(ConfigError::ConflictingHeaderAdd {
                field,
                name: "cookie_path.from".to_owned(),
            });
        }
    }

    Ok(())
}

pub fn validate_header_add_aliases(
    field: &'static str,
    set: &BTreeMap<String, String>,
    add: &BTreeMap<String, String>,
    operations_add: &BTreeMap<String, String>,
) -> Result<(), ConfigError> {
    let mut seen = std::collections::BTreeSet::new();
    for name in set.keys() {
        seen.insert(name.to_ascii_lowercase());
    }
    for name in add.keys().chain(operations_add.keys()) {
        let normalized = name.to_ascii_lowercase();
        if !seen.insert(normalized) {
            return Err(ConfigError::ConflictingHeaderAdd {
                field,
                name: name.clone(),
            });
        }
    }

    Ok(())
}

pub fn combined_header_unset(
    unset: &[String],
    remove: &[String],
    operations_remove: &[String],
) -> Vec<String> {
    let mut combined = Vec::with_capacity(unset.len() + remove.len() + operations_remove.len());
    combined.extend(unset.iter().cloned());
    combined.extend(remove.iter().cloned());
    combined.extend(operations_remove.iter().cloned());
    combined
}

pub fn combined_header_set(
    set: &BTreeMap<String, String>,
    add: &BTreeMap<String, String>,
    operations_add: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut combined = set.clone();
    combined.extend(
        add.iter()
            .map(|(name, value)| (name.clone(), value.clone())),
    );
    combined.extend(
        operations_add
            .iter()
            .map(|(name, value)| (name.clone(), value.clone())),
    );
    combined
}

pub fn merge_header_mutations(
    unset: &mut Vec<String>,
    set: &mut BTreeMap<String, String>,
    append: &mut BTreeMap<String, HeaderValues>,
    overlay_unset: &[String],
    overlay_set: &BTreeMap<String, String>,
    overlay_append: &BTreeMap<String, HeaderValues>,
) {
    unset.extend(overlay_unset.iter().cloned());
    for (name, value) in overlay_set {
        set.insert(name.clone(), value.clone());
    }
    for (name, values) in overlay_append {
        append
            .entry(name.clone())
            .and_modify(|existing| existing.extend(values))
            .or_insert_with(|| values.clone());
    }
}

pub fn validate_header_name(field: &'static str, name: &str) -> Result<(), ConfigError> {
    let normalized = name.trim();
    if normalized != name || !valid_http_header_name(name) {
        return Err(ConfigError::InvalidHeaderName {
            field,
            name: name.to_owned(),
        });
    }

    Ok(())
}

pub fn validate_dynamic_header_template(
    field: &'static str,
    name: &str,
    value: &str,
) -> Result<(), ConfigError> {
    let mut rest = value;
    while let Some(open) = rest.find('{') {
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('}') else {
            return Err(ConfigError::InvalidHeaderTemplate {
                field,
                name: name.to_owned(),
                variable: after_open.to_owned(),
            });
        };
        let variable = &after_open[..close];
        if !valid_dynamic_header_variable(variable) {
            return Err(ConfigError::InvalidHeaderTemplate {
                field,
                name: name.to_owned(),
                variable: variable.to_owned(),
            });
        }
        rest = &after_open[close + 1..];
    }

    if let Some(variable) = rest.split_once('}').map(|(before, _)| before) {
        return Err(ConfigError::InvalidHeaderTemplate {
            field,
            name: name.to_owned(),
            variable: variable.to_owned(),
        });
    }

    Ok(())
}

pub fn valid_dynamic_header_variable(variable: &str) -> bool {
    matches!(
        variable,
        "host"
            | "remote_addr"
            | "scheme"
            | "uri"
            | "path"
            | "query"
            | "request_id"
            | "tls.cipher"
            | "tls.version"
            | "tls.client_cert_organization"
            | "tls.client_cert_serial"
            | "tls.client_cert_sha256"
    ) || variable
        .strip_prefix("route.regex.")
        .is_some_and(valid_route_regex_capture_variable)
        || variable
            .strip_prefix("http.")
            .is_some_and(valid_http_header_name)
}

pub fn valid_route_regex_capture_variable(value: &str) -> bool {
    if value
        .parse::<usize>()
        .is_ok_and(|index| index < MAX_ROUTE_REGEX_CAPTURE_VALUES)
    {
        return true;
    }
    value.len() <= MAX_ROUTE_REGEX_CAPTURE_NAME_BYTES
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

pub fn valid_http_header_name(name: &str) -> bool {
    !name.is_empty()
        && name.bytes().all(|byte| {
            matches!(
                byte,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
                    | b'0'..=b'9'
                    | b'A'..=b'Z'
                    | b'a'..=b'z'
            )
        })
}

fn header_value_uses_tls_template(value: &str) -> bool {
    let mut rest = value;
    while let Some(open) = rest.find('{') {
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('}') else {
            return false;
        };
        if after_open[..close].starts_with("tls.") {
            return true;
        }
        rest = &after_open[close + 1..];
    }
    false
}

fn validate_header_mutation_value(
    field: &'static str,
    name: &str,
    value: &str,
) -> Result<(), ConfigError> {
    if value.trim().is_empty() || header_value_contains_disallowed_control(value) {
        return Err(ConfigError::InvalidHeaderValue {
            field,
            name: name.to_owned(),
        });
    }

    validate_dynamic_header_template(field, name, value)?;
    Ok(())
}

fn header_value_contains_disallowed_control(value: &str) -> bool {
    value
        .as_bytes()
        .iter()
        .any(|byte| matches!(byte, 0x00..=0x1f | 0x7f))
}

fn validate_response_header_rewrite_endpoint(
    field: &'static str,
    header: &'static str,
    side: &'static str,
    value: &str,
) -> Result<(), ConfigError> {
    let valid_prefix =
        value.starts_with("http://") || value.starts_with("https://") || value.starts_with('/');
    let valid_path_prefix = !value.starts_with("//");
    if value.is_empty()
        || value.len() > 2048
        || !valid_prefix
        || !valid_path_prefix
        || header_value_contains_disallowed_control(value)
    {
        return Err(ConfigError::InvalidHeaderValue {
            field,
            name: format!("{header}.{side}"),
        });
    }

    Ok(())
}

fn validate_cookie_domain_rewrite_endpoint(
    field: &'static str,
    side: &'static str,
    value: &str,
) -> Result<(), ConfigError> {
    let trimmed = value.trim();
    if trimmed.is_empty()
        || trimmed != value
        || value.len() > 255
        || value.starts_with('-')
        || value.ends_with('-')
        || value.contains("..")
        || value
            .bytes()
            .any(|byte| !(byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.')))
    {
        return Err(ConfigError::InvalidHeaderValue {
            field,
            name: format!("cookie_domain.{side}"),
        });
    }

    Ok(())
}

fn validate_cookie_path_rewrite_endpoint(
    field: &'static str,
    side: &'static str,
    value: &str,
) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > 2048
        || !value.starts_with('/')
        || value.starts_with("//")
        || value
            .bytes()
            .any(|byte| matches!(byte, 0x00..=0x20 | 0x7f | b';'))
    {
        return Err(ConfigError::InvalidHeaderValue {
            field,
            name: format!("cookie_path.{side}"),
        });
    }

    Ok(())
}

fn validate_header_mutation_len(
    field: &'static str,
    operation: &'static str,
    len: usize,
    max: usize,
) -> Result<(), ConfigError> {
    if len > max {
        return Err(ConfigError::InvalidHeaderMutationLength {
            field,
            operation,
            max,
        });
    }
    Ok(())
}
