use std::collections::HashSet;

use crate::config::{ConfigError, MAX_ROUTE_REGEX_PROGRAM_BYTES, valid_http_token};
use crate::config_header::valid_route_regex_capture_variable;

const MAX_ROUTE_METHODS: usize = 16;
const MAX_ROUTE_REGEX_BYTES: usize = 4096;

pub(crate) fn validate_route_path(
    _field: &'static str,
    value: &str,
    _prefix: bool,
) -> Result<(), ConfigError> {
    if !value.starts_with('/')
        || value.contains('\0')
        || value.contains('\\')
        || value.contains('?')
        || value.contains('#')
        || value.chars().any(char::is_control)
        || value.split('/').any(|segment| segment == "..")
    {
        return Err(ConfigError::InvalidRouteMatcher {
            vhost: String::new(),
            route: String::new(),
        });
    }
    Ok(())
}

pub(crate) fn validate_route_rewrite_prefix_path(value: &str) -> Result<(), ConfigError> {
    validate_route_path("vhosts.routes.rewrite_prefix", value, true)?;
    if value.contains('%') || value.chars().any(char::is_whitespace) {
        return Err(ConfigError::InvalidRouteMatcher {
            vhost: String::new(),
            route: String::new(),
        });
    }
    Ok(())
}

pub(crate) fn validate_route_rewrite_template_path(value: &str) -> Result<(), ConfigError> {
    if !value.starts_with('/')
        || value.contains('\0')
        || value.contains('\\')
        || value.contains('?')
        || value.contains('#')
        || value.contains('%')
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return Err(ConfigError::InvalidRouteMatcher {
            vhost: String::new(),
            route: String::new(),
        });
    }

    let mut rest = value;
    while let Some(open) = rest.find('{') {
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('}') else {
            return Err(ConfigError::InvalidRouteMatcher {
                vhost: String::new(),
                route: String::new(),
            });
        };
        let variable = &after_open[..close];
        if !variable
            .strip_prefix("route.regex.")
            .is_some_and(valid_route_regex_capture_variable)
        {
            return Err(ConfigError::InvalidRouteMatcher {
                vhost: String::new(),
                route: String::new(),
            });
        }
        rest = &after_open[close + 1..];
    }

    if rest.contains('}') {
        return Err(ConfigError::InvalidRouteMatcher {
            vhost: String::new(),
            route: String::new(),
        });
    }

    Ok(())
}

pub(crate) fn validate_route_regex(value: &str) -> Result<(), ConfigError> {
    if value.is_empty()
        || value.len() > MAX_ROUTE_REGEX_BYTES
        || value.contains('\0')
        || value.chars().any(char::is_control)
    {
        return Err(ConfigError::InvalidRouteRegex {
            vhost: String::new(),
            route: String::new(),
        });
    }
    regex::RegexBuilder::new(value)
        .size_limit(MAX_ROUTE_REGEX_PROGRAM_BYTES)
        .build()
        .map_err(|_| ConfigError::InvalidRouteRegex {
            vhost: String::new(),
            route: String::new(),
        })?;
    Ok(())
}

pub(crate) fn validate_route_methods(
    vhost: &str,
    route: &str,
    methods: &[String],
) -> Result<(), ConfigError> {
    if methods.len() > MAX_ROUTE_METHODS {
        return Err(ConfigError::InvalidRouteMethods {
            vhost: vhost.to_owned(),
            route: route.to_owned(),
            reason: "at most 16 methods are allowed",
        });
    }

    let mut seen = HashSet::new();
    for method in methods {
        if method.is_empty()
            || method.len() > 32
            || !valid_http_token(method)
            || method.chars().any(char::is_lowercase)
        {
            return Err(ConfigError::InvalidRouteMethods {
                vhost: vhost.to_owned(),
                route: route.to_owned(),
                reason: "methods must be uppercase HTTP method tokens",
            });
        }
        if !seen.insert(method) {
            return Err(ConfigError::InvalidRouteMethods {
                vhost: vhost.to_owned(),
                route: route.to_owned(),
                reason: "contains duplicate methods",
            });
        }
    }
    Ok(())
}

pub(crate) fn valid_redirect_target_template(value: &str) -> bool {
    let value = value.trim();
    if !(value.starts_with("https://") || value.starts_with("http://"))
        || value
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
    {
        return false;
    }

    let expanded = value
        .replace("{uri}", "/")
        .replace("{path}", "/")
        .replace("{query}", "");
    if expanded.contains('{') || expanded.contains('}') {
        return false;
    }
    if expanded.contains("\\") {
        return false;
    }

    let Some(rest) = expanded
        .strip_prefix("https://")
        .or_else(|| expanded.strip_prefix("http://"))
    else {
        return false;
    };
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default()
        .trim_matches(['[', ']']);
    !authority.is_empty()
        && !authority.contains('@')
        && !authority.contains('\\')
        && !authority.chars().any(|character| {
            character.is_control() || character.is_whitespace() || matches!(character, '/' | '#')
        })
}
