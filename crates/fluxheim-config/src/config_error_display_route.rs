use std::fmt::Formatter;

use super::kind::ConfigError;

pub(super) fn format_route_error(
    error: &ConfigError,
    formatter: &mut Formatter<'_>,
) -> std::fmt::Result {
    match error {
        ConfigError::EmptyWebRoot => write!(formatter, "web root cannot be empty"),
        ConfigError::EmptyIndexFiles => {
            write!(formatter, "at least one web index file is required")
        }
        ConfigError::InvalidIndexFile { file } => write!(
            formatter,
            "web index file must be a plain file name, got {file:?}"
        ),
        ConfigError::EmptyVhostName => write!(formatter, "vhost name cannot be empty"),
        ConfigError::EmptyVhostHosts { vhost } => {
            write!(formatter, "vhost {vhost:?} must define at least one host")
        }
        ConfigError::InvalidVhostHost { vhost, host } => {
            write!(formatter, "vhost {vhost:?} has invalid host {host:?}")
        }
        ConfigError::InvalidVhostLimit { vhost, field } => {
            write!(
                formatter,
                "vhost {vhost:?} {field} must be greater than zero"
            )
        }
        ConfigError::InvalidAccessRule { field, value } => write!(
            formatter,
            "{field} entries must be IP addresses or CIDR ranges, got {value:?}"
        ),
        ConfigError::DuplicateAccessRule { field, value } => {
            write!(formatter, "{field} contains duplicate entry {value:?}")
        }
        ConfigError::InvalidRateLimit { field } => {
            write!(formatter, "{field} contains an invalid rate limit value")
        }
        ConfigError::InvalidConcurrencyLimit { field } => {
            write!(
                formatter,
                "{field} contains an invalid concurrency limit value"
            )
        }
        ConfigError::MissingVhostRedirectTarget { vhost } => write!(
            formatter,
            "vhost {vhost:?} redirect.enabled requires redirect.to"
        ),
        ConfigError::VhostRedirectConflictsWithFallback { vhost } => write!(
            formatter,
            "vhost {vhost:?} redirect.enabled cannot be combined with an explicit fallback route"
        ),
        ConfigError::EmptyRouteName { vhost } => {
            write!(
                formatter,
                "vhost {vhost:?} contains a route with an empty name"
            )
        }
        ConfigError::InvalidRouteMatcher { vhost, route } => write!(
            formatter,
            "vhost {vhost:?} route {route:?} must define exactly one of path_exact, path_prefix, path_regex, or fallback = true"
        ),
        ConfigError::RouteRegexDisabled { vhost, route } => write!(
            formatter,
            "vhost {vhost:?} route {route:?} uses path_regex but server.regex_enabled is false"
        ),
        ConfigError::InvalidRouteRegex { vhost, route } => write!(
            formatter,
            "vhost {vhost:?} route {route:?} path_regex must be a valid bounded Rust regex for request paths"
        ),
        ConfigError::InvalidRouteMethods {
            vhost,
            route,
            reason,
        } => write!(
            formatter,
            "vhost {vhost:?} route {route:?} methods policy is invalid: {reason}"
        ),
        ConfigError::DuplicateFallbackRoute { vhost } => {
            write!(
                formatter,
                "vhost {vhost:?} defines more than one fallback route"
            )
        }
        ConfigError::InvalidRouteStripPrefix { vhost, route } => write!(
            formatter,
            "vhost {vhost:?} route {route:?} strip_prefix must be an absolute path prefix attached to path_prefix"
        ),
        ConfigError::InvalidRouteRewritePrefix { vhost, route } => write!(
            formatter,
            "vhost {vhost:?} route {route:?} rewrite_prefix must be an absolute path prefix attached to strip_prefix"
        ),
        ConfigError::InvalidRouteRewriteTemplate { vhost, route } => write!(
            formatter,
            "vhost {vhost:?} route {route:?} rewrite_template must be an absolute path template attached to path_regex and cannot be combined with strip_prefix or rewrite_prefix"
        ),
        ConfigError::InvalidRouteAction { vhost, route } => write!(
            formatter,
            "vhost {vhost:?} route {route:?} must define exactly one action: redirect, proxy, or web"
        ),
        ConfigError::InvalidRouteGrpcPolicy {
            vhost,
            route,
            reason,
        } => write!(
            formatter,
            "vhost {vhost:?} route {route:?} grpc policy is invalid: {reason}"
        ),
        ConfigError::InvalidRouteLimit {
            vhost,
            route,
            field,
        } => write!(
            formatter,
            "vhost {vhost:?} route {route:?} {field} must be greater than zero"
        ),
        ConfigError::InvalidRouteRedirectStatus {
            vhost,
            route,
            status,
        } => write!(
            formatter,
            "vhost {vhost:?} route {route:?} redirect.status must be one of 301, 302, 307, or 308, got {status}"
        ),
        ConfigError::InvalidRouteRedirectTarget { vhost, route } => write!(
            formatter,
            "vhost {vhost:?} route {route:?} redirect.to must be a safe absolute http(s) URL template"
        ),
        ConfigError::VhostSection {
            vhost,
            section,
            source,
        } => write!(formatter, "vhost {vhost:?} {section}: {source}"),
        ConfigError::RouteSection {
            vhost,
            route,
            section,
            source,
        } => write!(
            formatter,
            "vhost {vhost:?} route {route:?} {section}: {source}"
        ),
        ConfigError::DuplicateVhostName { name } => {
            write!(formatter, "duplicate vhost name {name:?}")
        }
        ConfigError::DuplicateVhostHost { host } => {
            write!(formatter, "duplicate vhost host {host:?}")
        }
        _ => formatter.write_str("invalid route config error"),
    }
}
