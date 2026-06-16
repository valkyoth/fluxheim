#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use std::net::IpAddr;

use fluxheim_config::{ResponseHeaderRewriteConfig, ResponseHeaderRewriteRuleConfig};

pub const SPOOFABLE_CLIENT_IP_HEADERS: &[&str] = &[
    "x-forwarded-for",
    "x-real-ip",
    "forwarded",
    "cf-connecting-ip",
    "true-client-ip",
    "x-client-ip",
    "x-cluster-client-ip",
    "fastly-client-ip",
];

pub const DEFAULT_SERVER_HEADER: &str = "fluxheim";

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
    let match_start = if matches!(value.as_bytes().get(url_start), Some(b'"' | b'\'')) {
        url_start + 1
    } else {
        url_start
    };
    let rewritten_url = rewrite_header_prefix(&value[match_start..], rules)?;
    let mut rewritten = String::with_capacity(match_start + rewritten_url.len());
    rewritten.push_str(&value[..match_start]);
    rewritten.push_str(&rewritten_url);
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

pub fn effective_client_ip(
    direct_ip: IpAddr,
    trusted_direct_peer: bool,
    original_x_forwarded_for: Option<&str>,
    trusted_proxy_matcher: Option<&dyn Fn(IpAddr) -> bool>,
) -> IpAddr {
    if !trusted_direct_peer {
        return direct_ip;
    }

    let Some(original_x_forwarded_for) = original_x_forwarded_for else {
        return direct_ip;
    };
    let Some(trusted_proxy_matcher) = trusted_proxy_matcher else {
        return direct_ip;
    };

    let mut last_valid_hop = None;
    for hop in original_x_forwarded_for
        .split(',')
        .rev()
        .filter_map(parse_x_forwarded_for_ip)
    {
        last_valid_hop.get_or_insert(hop);
        if !trusted_proxy_matcher(hop) {
            return hop;
        }
    }

    last_valid_hop.unwrap_or(direct_ip)
}

pub fn parse_x_forwarded_for_ip(value: &str) -> Option<IpAddr> {
    let value = value.trim().trim_matches('"');
    if value.is_empty() {
        return None;
    }
    if let Some(value) = value
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    {
        return value.parse().ok();
    }
    value.parse().ok()
}

pub fn build_forwarded_header(client_ip: IpAddr, host: Option<&str>, proto: &str) -> String {
    let mut value = format!("for={}", forwarded_ip(client_ip));
    if let Some(host) = host {
        value.push_str(";host=");
        value.push_str(&quote_forwarded_value(host));
    }
    value.push_str(";proto=");
    value.push_str(proto);
    value
}

fn forwarded_ip(client_ip: IpAddr) -> String {
    match client_ip {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("\"[{ip}]\""),
    }
}

fn quote_forwarded_value(value: &str) -> String {
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for character in value.chars() {
        if matches!(character, '\\' | '"') {
            quoted.push('\\');
        }
        quoted.push(character);
    }
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    use fluxheim_config::{ResponseHeaderRewriteConfig, ResponseHeaderRewriteRuleConfig};

    use super::{
        build_forwarded_header, effective_client_ip, parse_x_forwarded_for_ip,
        rewrite_header_prefix, rewrite_refresh_url, rewrite_set_cookie_value,
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
    }

    #[test]
    fn parses_forwarded_for_ip_shapes() {
        assert_eq!(
            parse_x_forwarded_for_ip(" 198.51.100.10 "),
            Some(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 10)))
        );
        assert_eq!(
            parse_x_forwarded_for_ip("\"[2001:db8::1]\""),
            Some(IpAddr::V6("2001:db8::1".parse().expect("valid IPv6")))
        );
        assert_eq!(parse_x_forwarded_for_ip("not-an-ip"), None);
    }

    #[test]
    fn restores_client_ip_from_trusted_forwarded_chain() {
        let direct = IpAddr::V4(Ipv4Addr::new(10, 89, 0, 254));
        let matcher = |address: IpAddr| match address {
            IpAddr::V4(address) => {
                address == Ipv4Addr::new(10, 89, 0, 254)
                    || address == Ipv4Addr::new(203, 0, 113, 10)
            }
            IpAddr::V6(_) => false,
        };

        assert_eq!(
            effective_client_ip(
                direct,
                true,
                Some("198.51.100.9, 203.0.113.10"),
                Some(&matcher),
            ),
            IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9))
        );
        assert_eq!(
            effective_client_ip(direct, false, Some("198.51.100.9"), Some(&matcher)),
            direct
        );
    }

    #[test]
    fn builds_forwarded_header_values() {
        assert_eq!(
            build_forwarded_header(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 9)),
                Some("example.test"),
                "https"
            ),
            "for=198.51.100.9;host=\"example.test\";proto=https"
        );
        assert_eq!(
            build_forwarded_header(IpAddr::V6(Ipv6Addr::LOCALHOST), None, "https"),
            "for=\"[::1]\";proto=https"
        );
    }
}
