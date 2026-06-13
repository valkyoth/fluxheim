use crate::flux_error::{FluxError, FluxResult};
use crate::http_types::PingoraRequestHeader as RequestHeader;
use crate::path_safety::safe_forward_path;
pub(crate) use fluxheim_protocol::route_method_matches;
use fluxheim_protocol::{route_prefix_matches_path, route_strip_prefix_suffix};

#[derive(Debug, Clone)]
pub(crate) enum RuntimeRouteMatcher {
    Exact(String),
    Prefix(String),
    Regex(regex::Regex),
    Fallback,
}

const MAX_ROUTE_REGEX_CAPTURE_VALUES: usize = 16;
const MAX_ROUTE_REGEX_CAPTURE_VALUE_BYTES: usize = 256;

impl RuntimeRouteMatcher {
    pub(crate) fn from_config(
        vhost_name: &str,
        route: &crate::config::RouteConfig,
    ) -> FluxResult<Self> {
        if let Some(path) = &route.path_exact {
            Ok(Self::Exact(path.clone()))
        } else if let Some(path) = &route.path_prefix {
            Ok(Self::Prefix(path.clone()))
        } else if let Some(pattern) = &route.path_regex {
            Ok(Self::Regex(
                regex::RegexBuilder::new(pattern)
                    .size_limit(crate::config::MAX_ROUTE_REGEX_PROGRAM_BYTES)
                    .build()
                    .map_err(|error| {
                        FluxError::invalid_input(format!(
                            "vhost {vhost_name:?} route {:?} path_regex failed to compile: {error}",
                            route.name
                        ))
                    })?,
            ))
        } else {
            Ok(Self::Fallback)
        }
    }

    pub(crate) fn matches_path(&self, path: &str) -> bool {
        match self {
            Self::Exact(exact) => path == exact,
            Self::Prefix(prefix) => route_prefix_matches_path(prefix, path),
            Self::Regex(regex) => regex.is_match(path),
            Self::Fallback => true,
        }
    }

    pub(crate) fn prefix_len(&self) -> Option<usize> {
        match self {
            Self::Prefix(prefix) => Some(prefix.len()),
            _ => None,
        }
    }
}

pub(crate) fn route_regex_captures(
    matcher: &RuntimeRouteMatcher,
    path: &str,
) -> Option<crate::headers::RouteRegexCaptures> {
    let RuntimeRouteMatcher::Regex(regex) = matcher else {
        return None;
    };
    let captures = regex.captures(path)?;
    Some(route_regex_captures_from_matches(regex, &captures))
}

pub(crate) fn route_rewritten_path_and_query(
    request: &RequestHeader,
    matcher: &RuntimeRouteMatcher,
    strip_prefix: Option<&str>,
    rewrite_prefix: Option<&str>,
    rewrite_template: Option<&str>,
) -> Option<String> {
    let rewritten_path = route_rewritten_path(
        request.uri.path(),
        matcher,
        strip_prefix,
        rewrite_prefix,
        rewrite_template,
    )?;
    with_original_query(request, rewritten_path)
}

pub(crate) fn route_rewritten_path(
    path: &str,
    matcher: &RuntimeRouteMatcher,
    strip_prefix: Option<&str>,
    rewrite_prefix: Option<&str>,
    rewrite_template: Option<&str>,
) -> Option<String> {
    if let Some(template) = rewrite_template {
        let rewritten_path = route_rewrite_template_path(path, matcher, template)?;
        return safe_forward_path(&rewritten_path).then_some(rewritten_path);
    }
    let strip_prefix = strip_prefix?;
    let suffix = route_strip_prefix_suffix(strip_prefix, path)?;
    let rewritten_path = if let Some(rewrite_prefix) = rewrite_prefix {
        join_route_rewrite_prefix(rewrite_prefix, suffix)?
    } else if suffix.is_empty() {
        "/".to_owned()
    } else if suffix.starts_with('/') {
        suffix.to_owned()
    } else {
        format!("/{suffix}")
    };
    if !safe_forward_path(&rewritten_path) {
        return None;
    }
    Some(rewritten_path)
}

fn with_original_query(request: &RequestHeader, rewritten_path: String) -> Option<String> {
    match request.uri.query() {
        Some(query) => Some(format!("{rewritten_path}?{query}")),
        None => Some(rewritten_path),
    }
}

fn route_rewrite_template_path(
    path: &str,
    matcher: &RuntimeRouteMatcher,
    template: &str,
) -> Option<String> {
    let RuntimeRouteMatcher::Regex(regex) = matcher else {
        return None;
    };
    let captures = regex.captures(path)?;
    let captures = route_regex_captures_from_matches(regex, &captures);
    let mut rewritten = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        rewritten.push_str(&rest[..open]);
        let after_open = &rest[open + 1..];
        let close = after_open.find('}')?;
        let variable = &after_open[..close];
        if let Some(value) = captures.variable(variable) {
            append_route_regex_capture_value(&mut rewritten, value);
        }
        rest = &after_open[close + 1..];
    }
    rewritten.push_str(rest);
    if rewritten.contains('{') || rewritten.contains('}') {
        return None;
    }
    Some(rewritten)
}

fn route_regex_captures_from_matches(
    regex: &regex::Regex,
    captures: &regex::Captures<'_>,
) -> crate::headers::RouteRegexCaptures {
    let numbered = captures
        .iter()
        .take(MAX_ROUTE_REGEX_CAPTURE_VALUES)
        .map(bounded_route_regex_capture)
        .collect::<Vec<_>>();
    let named = regex
        .capture_names()
        .enumerate()
        .take(MAX_ROUTE_REGEX_CAPTURE_VALUES)
        .filter_map(|(index, name)| {
            name.and_then(|name| {
                captures
                    .get(index)
                    .and_then(|value| bounded_route_regex_capture(Some(value)))
                    .map(|value| (name.to_owned(), value))
            })
        })
        .collect::<std::collections::BTreeMap<_, _>>();

    crate::headers::RouteRegexCaptures::new(numbered, named)
}

fn bounded_route_regex_capture(value: Option<regex::Match<'_>>) -> Option<String> {
    let value = value?.as_str();
    (value.len() <= MAX_ROUTE_REGEX_CAPTURE_VALUE_BYTES).then(|| value.to_owned())
}

fn append_route_regex_capture_value(rewritten: &mut String, value: &str) {
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') {
            rewritten.push(char::from(byte));
        } else {
            static HEX: &[u8; 16] = b"0123456789ABCDEF";
            rewritten.push('%');
            rewritten.push(char::from(HEX[usize::from(byte >> 4)]));
            rewritten.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
}

fn join_route_rewrite_prefix(rewrite_prefix: &str, suffix: &str) -> Option<String> {
    if rewrite_prefix == "/" {
        return Some(if suffix.is_empty() {
            "/".to_owned()
        } else if suffix.starts_with('/') {
            suffix.to_owned()
        } else {
            format!("/{suffix}")
        });
    }

    let rewritten_path = if suffix.is_empty() {
        rewrite_prefix.to_owned()
    } else if rewrite_prefix.ends_with('/') && suffix.starts_with('/') {
        format!("{}{}", rewrite_prefix, &suffix[1..])
    } else if rewrite_prefix.ends_with('/') || suffix.starts_with('/') {
        format!("{rewrite_prefix}{suffix}")
    } else {
        format!("{rewrite_prefix}/{suffix}")
    };

    safe_forward_path(&rewritten_path).then_some(rewritten_path)
}

#[cfg(test)]
mod tests {
    use super::{RuntimeRouteMatcher, route_method_matches, route_rewritten_path};

    #[test]
    fn route_method_matching_treats_inbound_case_as_equivalent() {
        let methods = vec!["GET".to_owned(), "HEAD".to_owned()];

        assert!(route_method_matches(&methods, "GET"));
        assert!(route_method_matches(&methods, "get"));
        assert!(route_method_matches(&methods, "Head"));
        assert!(!route_method_matches(&methods, "POST"));
    }

    #[test]
    fn prefix_routes_require_path_segment_boundary() {
        let matcher = RuntimeRouteMatcher::Prefix("/repo".to_owned());

        assert!(matcher.matches_path("/repo"));
        assert!(matcher.matches_path("/repo/admin"));
        assert!(!matcher.matches_path("/repoadmin"));
        assert!(!matcher.matches_path("/repository/admin"));
    }

    #[test]
    fn regex_rewrite_capture_values_are_percent_encoded() {
        let matcher = RuntimeRouteMatcher::Regex(
            regex::Regex::new(r"^/api/(?P<version>[^/]+)/(?P<rest>.*)$").unwrap(),
        );

        assert_eq!(
            route_rewritten_path(
                "/api/1;jsessionid=admin/users%3Badmin",
                &matcher,
                None,
                None,
                Some("/v{route.regex.version}/{route.regex.rest}")
            )
            .as_deref(),
            Some("/v1%3Bjsessionid%3Dadmin/users%253Badmin")
        );
    }
}
