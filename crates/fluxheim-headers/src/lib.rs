#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use fluxheim_config::{ResponseHeaderRewriteConfig, ResponseHeaderRewriteRuleConfig};

#[cfg(not(feature = "privacy-mode"))]
mod client_ip;
mod hop_by_hop;

#[cfg(not(feature = "privacy-mode"))]
pub use client_ip::{
    ForwardedProto, build_forwarded_header, effective_client_ip, parse_x_forwarded_for_ip,
};
pub use hop_by_hop::{
    HOP_BY_HOP_REQUEST_HEADERS, HopByHopRequestHeaderPolicy, hop_by_hop_request_header_policy,
};

pub const SPOOFABLE_CLIENT_IP_HEADERS: &[&str] = &[
    "x-forwarded-for",
    "x-real-ip",
    "forwarded",
    "x-forwarded-host",
    "x-forwarded-proto",
    "cf-connecting-ip",
    "true-client-ip",
    "x-client-ip",
    "client-ip",
    "x-cluster-client-ip",
    "fastly-client-ip",
    "x-envoy-external-address",
    "x-original-forwarded-for",
    "x-azure-clientip",
    "fly-client-ip",
    "x-proxyuser-ip",
    "x-forwarded-client-cert",
];

pub const DEFAULT_SERVER_HEADER: &str = "fluxheim";

#[derive(Clone, Debug, Default)]
pub struct RequestTlsClientIdentity {
    pub cipher: Option<String>,
    pub version: Option<String>,
    pub organization: Option<String>,
    pub serial_number: Option<String>,
    pub cert_sha256: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct RouteRegexCaptures {
    numbered: Vec<Option<String>>,
    named: std::collections::BTreeMap<String, String>,
}

impl RouteRegexCaptures {
    pub fn new(
        numbered: Vec<Option<String>>,
        named: std::collections::BTreeMap<String, String>,
    ) -> Self {
        Self { numbered, named }
    }

    pub fn variable(&self, variable: &str) -> Option<&str> {
        let key = variable.strip_prefix("route.regex.")?;
        if key.bytes().all(|byte| byte.is_ascii_digit()) {
            return key
                .parse::<usize>()
                .ok()
                .and_then(|index| self.numbered.get(index))
                .and_then(Option::as_deref);
        }
        self.named.get(key).map(String::as_str)
    }
}

pub fn join_header_values<'a>(values: impl IntoIterator<Item = &'a str>) -> Option<String> {
    join_header_values_with_separator(values, ", ")
}

pub fn join_header_values_with_separator<'a>(
    values: impl IntoIterator<Item = &'a str>,
    separator: &str,
) -> Option<String> {
    let mut values = values.into_iter();
    let first = values.next()?.to_owned();
    Some(values.fold(first, |mut joined, value| {
        joined.push_str(separator);
        joined.push_str(value);
        joined
    }))
}

pub fn rewrite_header_prefix(
    value: &str,
    rules: &[ResponseHeaderRewriteRuleConfig],
) -> Option<String> {
    for rule in rules {
        if fluxheim_protocol::response_rewrite_prefix_matches(value, &rule.from) {
            let mut rewritten =
                String::with_capacity(rule.to.len() + value.len() - rule.from.len());
            rewritten.push_str(&rule.to);
            rewritten.push_str(&value[rule.from.len()..]);
            return Some(rewritten);
        }
    }
    None
}

pub fn rewrite_refresh_url(
    value: &str,
    rules: &[ResponseHeaderRewriteRuleConfig],
) -> Option<String> {
    let url_start = find_refresh_url_start(value)?;
    let quote = value
        .as_bytes()
        .get(url_start)
        .copied()
        .filter(|byte| matches!(byte, b'"' | b'\''));
    let match_start = url_start.checked_add(usize::from(quote.is_some()))?;
    let match_end = match quote {
        Some(quote) => {
            let relative_end = value[match_start..].find(char::from(quote))?;
            match_start.checked_add(relative_end)?
        }
        None => value.len(),
    };
    let rewritten_url = rewrite_header_prefix(&value[match_start..match_end], rules)?;
    let capacity = value
        .len()
        .checked_sub(match_end.checked_sub(match_start)?)?
        .checked_add(rewritten_url.len())?;
    let mut rewritten = String::with_capacity(capacity);
    rewritten.push_str(&value[..match_start]);
    rewritten.push_str(&rewritten_url);
    rewritten.push_str(&value[match_end..]);
    Some(rewritten)
}

fn find_refresh_url_start(value: &str) -> Option<usize> {
    let bytes = value.as_bytes();
    let mut index = 0;
    while index + 3 <= bytes.len() {
        let previous_is_separator = index == 0 || matches!(bytes[index - 1], b';' | b' ' | b'\t');
        if previous_is_separator && bytes[index..index + 3].eq_ignore_ascii_case(b"url") {
            let mut cursor = index + 3;
            while bytes
                .get(cursor)
                .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
            {
                cursor += 1;
            }
            if bytes.get(cursor) == Some(&b'=') {
                cursor += 1;
                while bytes
                    .get(cursor)
                    .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
                {
                    cursor += 1;
                }
                return Some(cursor);
            }
        }
        index += 1;
    }
    None
}

pub fn rewrite_set_cookie_value(
    value: &str,
    rewrite: &ResponseHeaderRewriteConfig,
) -> Option<String> {
    let mut changed = false;
    let mut rewritten = String::with_capacity(value.len());
    for (index, segment) in value.split(';').enumerate() {
        if index > 0 {
            rewritten.push(';');
        }
        if index == 0 {
            rewritten.push_str(segment);
            continue;
        }
        if let Some(next) = rewrite_cookie_attribute(
            segment,
            "domain",
            &rewrite.cookie_domain,
            rewrite_cookie_domain,
        ) {
            rewritten.push_str(&next);
            changed = true;
        } else if let Some(next) =
            rewrite_cookie_attribute(segment, "path", &rewrite.cookie_path, rewrite_cookie_path)
        {
            rewritten.push_str(&next);
            changed = true;
        } else {
            rewritten.push_str(segment);
        }
    }

    changed.then_some(rewritten)
}

fn rewrite_cookie_attribute(
    segment: &str,
    attribute: &str,
    rules: &[ResponseHeaderRewriteRuleConfig],
    rewrite_value: fn(
        CookieAttributeValue<'_>,
        &[ResponseHeaderRewriteRuleConfig],
    ) -> Option<String>,
) -> Option<String> {
    if rules.is_empty() {
        return None;
    }
    let value_start = cookie_attribute_value_start(segment, attribute)?;
    let value = CookieAttributeValue::new(&segment[value_start..]);
    let rewritten_value = rewrite_value(value, rules)?;
    let mut rewritten = String::with_capacity(value_start + rewritten_value.len());
    rewritten.push_str(&segment[..value_start]);
    rewritten.push_str(&rewritten_value);
    Some(rewritten)
}

fn cookie_attribute_value_start(segment: &str, attribute: &str) -> Option<usize> {
    let bytes = segment.as_bytes();
    let mut cursor = 0;
    while bytes
        .get(cursor)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        cursor += 1;
    }
    if cursor + attribute.len() > bytes.len()
        || !bytes[cursor..cursor + attribute.len()].eq_ignore_ascii_case(attribute.as_bytes())
    {
        return None;
    }
    cursor += attribute.len();
    while bytes
        .get(cursor)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        cursor += 1;
    }
    if bytes.get(cursor) != Some(&b'=') {
        return None;
    }
    cursor += 1;
    while bytes
        .get(cursor)
        .is_some_and(|byte| matches!(byte, b' ' | b'\t'))
    {
        cursor += 1;
    }
    Some(cursor)
}

#[derive(Clone, Copy)]
struct CookieAttributeValue<'a> {
    normalized: &'a str,
}

impl<'a> CookieAttributeValue<'a> {
    fn new(value: &'a str) -> Self {
        let normalized = normalize_cookie_attribute_value(value);
        Self { normalized }
    }
}

fn normalize_cookie_attribute_value(value: &str) -> &str {
    let value = trim_cookie_attribute_ascii_whitespace(value);
    value
        .strip_prefix('"')
        .and_then(|value| value.strip_suffix('"'))
        .unwrap_or(value)
}

fn trim_cookie_attribute_ascii_whitespace(value: &str) -> &str {
    value.trim_matches(|character| matches!(character, ' ' | '\t'))
}

fn normalized_cookie_domain(value: &str) -> &str {
    normalize_cookie_attribute_value(value)
        .strip_prefix('.')
        .unwrap_or_else(|| normalize_cookie_attribute_value(value))
}

fn rewrite_cookie_domain(
    value: CookieAttributeValue<'_>,
    rules: &[ResponseHeaderRewriteRuleConfig],
) -> Option<String> {
    let value = value
        .normalized
        .strip_prefix('.')
        .unwrap_or(value.normalized);
    for rule in rules {
        if value.eq_ignore_ascii_case(normalized_cookie_domain(&rule.from)) {
            return Some(rule.to.clone());
        }
    }
    None
}

fn rewrite_cookie_path(
    value: CookieAttributeValue<'_>,
    rules: &[ResponseHeaderRewriteRuleConfig],
) -> Option<String> {
    rewrite_header_prefix(value.normalized, rules)
}

#[cfg(test)]
mod tests {
    use fluxheim_config::{ResponseHeaderRewriteConfig, ResponseHeaderRewriteRuleConfig};

    use super::{
        RouteRegexCaptures, SPOOFABLE_CLIENT_IP_HEADERS, join_header_values,
        join_header_values_with_separator, rewrite_header_prefix, rewrite_refresh_url,
        rewrite_set_cookie_value,
    };

    #[test]
    fn rewrites_header_prefix_with_authority_boundary() {
        let rules = [ResponseHeaderRewriteRuleConfig {
            from: "http://backend.internal".to_owned(),
            to: "https://example.test".to_owned(),
        }];

        assert_eq!(
            rewrite_header_prefix("http://backend.internal/login", &rules),
            Some("https://example.test/login".to_owned())
        );
        assert_eq!(
            rewrite_header_prefix("http://backend.internal@evil.example/login", &rules),
            None
        );
    }

    #[test]
    fn rewrites_refresh_url_values() {
        let rules = [ResponseHeaderRewriteRuleConfig {
            from: "http://backend.internal/".to_owned(),
            to: "https://example.test/".to_owned(),
        }];

        assert_eq!(
            rewrite_refresh_url("0; url = http://backend.internal/login", &rules),
            Some("0; url = https://example.test/login".to_owned())
        );
        assert_eq!(
            rewrite_refresh_url("0; url=\"http://backend.internal/login\"", &rules),
            Some("0; url=\"https://example.test/login\"".to_owned())
        );

        let origin_rules = [ResponseHeaderRewriteRuleConfig {
            from: "http://backend.internal".to_owned(),
            to: "https://example.test".to_owned(),
        }];
        assert_eq!(
            rewrite_refresh_url("0; url=\"http://backend.internal\"", &origin_rules),
            Some("0; url=\"https://example.test\"".to_owned())
        );
        assert_eq!(
            rewrite_refresh_url("0; url='http://backend.internal'; next", &origin_rules),
            Some("0; url='https://example.test'; next".to_owned())
        );
        assert_eq!(
            rewrite_refresh_url("0; url=\"http://backend.internal", &origin_rules),
            None
        );
    }

    #[test]
    fn rewrites_set_cookie_domain_and_path_values() {
        let rewrite = ResponseHeaderRewriteConfig {
            cookie_domain: vec![ResponseHeaderRewriteRuleConfig {
                from: ".backend.internal".to_owned(),
                to: "example.test".to_owned(),
            }],
            cookie_path: vec![ResponseHeaderRewriteRuleConfig {
                from: "/app/".to_owned(),
                to: "/".to_owned(),
            }],
            ..ResponseHeaderRewriteConfig::default()
        };

        assert_eq!(
            rewrite_set_cookie_value(
                "session=abc; Domain=BACKEND.internal; Path=/app/admin; HttpOnly",
                &rewrite
            ),
            Some("session=abc; Domain=example.test; Path=/admin; HttpOnly".to_owned())
        );
        assert_eq!(
            rewrite_set_cookie_value(
                "quoted=1; Domain=\"backend.internal\"; Path=\"/app/admin\"; HttpOnly",
                &rewrite
            ),
            Some("quoted=1; Domain=example.test; Path=/admin; HttpOnly".to_owned())
        );
        assert_eq!(
            rewrite_set_cookie_value("Domain=backend.internal; Secure", &rewrite),
            None
        );
        assert_eq!(
            rewrite_set_cookie_value("Path=/app/session; Secure", &rewrite),
            None
        );
    }

    #[test]
    fn spoofable_identity_headers_include_client_ip() {
        for expected in [
            "client-ip",
            "x-envoy-external-address",
            "x-original-forwarded-for",
            "x-azure-clientip",
            "fly-client-ip",
            "x-proxyuser-ip",
            "x-forwarded-client-cert",
        ] {
            assert!(
                SPOOFABLE_CLIENT_IP_HEADERS
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case(expected)),
                "missing spoofable identity header {expected}"
            );
        }
    }

    #[test]
    fn joins_repeated_header_values_for_forwarding() {
        assert_eq!(join_header_values(std::iter::empty()), None);
        assert_eq!(
            join_header_values(["one", "two", "three"]),
            Some("one, two, three".to_owned())
        );
        assert_eq!(
            join_header_values_with_separator(["a=1", "b=2"], "; "),
            Some("a=1; b=2".to_owned())
        );
    }

    #[test]
    fn route_regex_captures_resolve_numbered_and_named_variables() {
        let captures = RouteRegexCaptures::new(
            vec![Some("whole".to_owned()), Some("42".to_owned()), None],
            std::collections::BTreeMap::from([("slug".to_owned(), "article".to_owned())]),
        );

        assert_eq!(captures.variable("route.regex.0"), Some("whole"));
        assert_eq!(captures.variable("route.regex.1"), Some("42"));
        assert_eq!(captures.variable("route.regex.2"), None);
        assert_eq!(captures.variable("route.regex.slug"), Some("article"));
        assert_eq!(captures.variable("host"), None);
    }
}
