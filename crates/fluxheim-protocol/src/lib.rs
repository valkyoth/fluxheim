#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

mod http1;
mod proxy_protocol;

#[cfg(test)]
mod http1_tests;

pub use http1::{
    DEFAULT_HTTP1_MAX_HEAD_BYTES, DEFAULT_HTTP1_MAX_HEADER_COUNT,
    DEFAULT_HTTP1_MAX_HEADER_LINE_BYTES, DEFAULT_HTTP1_MAX_START_LINE_BYTES, Http1BodyFraming,
    Http1HeadBuffer, Http1HeadLimits, Http1Header, Http1ParseError, Http1RequestHead, Http1Version,
    http1_request_body_framing, parse_http1_request_head,
};
pub use proxy_protocol::{
    DownstreamProxyProtocolParseError, PROXY_PROTOCOL_V1_MAX_LINE, PROXY_PROTOCOL_V2_HEADER_LEN,
    PROXY_PROTOCOL_V2_MAX_PAYLOAD, PROXY_PROTOCOL_V2_SIGNATURE, ProxyProtocolTrustedSource,
    ProxyProtocolTrustedSourceParseError, parse_downstream_proxy_protocol_v1,
    parse_downstream_proxy_protocol_v2, parse_proxy_protocol_trusted_source,
    proxy_protocol_v1_header, proxy_protocol_v2_header,
};

pub fn route_method_matches(methods: &[String], method: &str) -> bool {
    methods.is_empty()
        || methods
            .iter()
            .any(|configured| configured.eq_ignore_ascii_case(method))
}

pub fn route_prefix_matches_path(prefix: &str, path: &str) -> bool {
    let Some(suffix) = path.strip_prefix(prefix) else {
        return false;
    };
    prefix == "/" || prefix.ends_with('/') || suffix.is_empty() || suffix.starts_with('/')
}

pub fn route_strip_prefix_suffix<'a>(strip_prefix: &str, path: &'a str) -> Option<&'a str> {
    let suffix = path.strip_prefix(strip_prefix)?;
    (strip_prefix == "/"
        || strip_prefix.ends_with('/')
        || suffix.is_empty()
        || suffix.starts_with('/'))
    .then_some(suffix)
}

/// Returns whether `value` is an RFC 7230 HTTP token.
///
/// HTTP tokens are case-sensitive octet strings at this layer. Callers that
/// validate HTTP methods or other uppercase-only policy fields must apply that
/// case policy separately.
pub fn http_token_valid(value: &str) -> bool {
    !value.is_empty()
        && value.bytes().all(|byte| {
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

pub fn http_upgrade_token_valid(value: &str) -> bool {
    http_token_valid(value)
}

pub const FLUXHEIM_VIA_VALUE: &str = "1.1 fluxheim";

pub fn append_fluxheim_via_value(existing: &str) -> String {
    if existing.trim().is_empty() {
        FLUXHEIM_VIA_VALUE.to_owned()
    } else {
        format!("{}, {}", existing.trim(), FLUXHEIM_VIA_VALUE)
    }
}

pub fn response_rewrite_prefix_matches(value: &str, prefix: &str) -> bool {
    if !value.starts_with(prefix) {
        return false;
    }
    if !response_rewrite_prefix_requires_authority_boundary(prefix) {
        return true;
    }
    matches!(
        value.as_bytes().get(prefix.len()),
        None | Some(b'/' | b'?' | b'#')
    )
}

fn response_rewrite_prefix_requires_authority_boundary(prefix: &str) -> bool {
    let Some(authority_and_path) = prefix
        .strip_prefix("http://")
        .or_else(|| prefix.strip_prefix("https://"))
    else {
        return false;
    };
    !authority_and_path
        .as_bytes()
        .iter()
        .any(|byte| matches!(byte, b'/' | b'?' | b'#'))
}

#[cfg(test)]
mod tests {
    use super::{
        append_fluxheim_via_value, http_token_valid, http_upgrade_token_valid,
        response_rewrite_prefix_matches, route_method_matches, route_prefix_matches_path,
        route_strip_prefix_suffix,
    };

    #[test]
    fn route_method_matching_treats_inbound_case_as_equivalent() {
        let methods = vec!["GET".to_owned(), "HEAD".to_owned()];

        assert!(route_method_matches(&methods, "GET"));
        assert!(route_method_matches(&methods, "get"));
        assert!(route_method_matches(&methods, "Head"));
        assert!(!route_method_matches(&methods, "POST"));
    }

    #[test]
    fn route_prefixes_require_path_segment_boundary() {
        assert!(route_prefix_matches_path("/repo", "/repo"));
        assert!(route_prefix_matches_path("/repo", "/repo/"));
        assert!(route_prefix_matches_path("/repo", "/repo/file"));
        assert!(!route_prefix_matches_path("/repo", "/repository"));
    }

    #[test]
    fn route_strip_prefix_requires_path_segment_boundary() {
        assert_eq!(route_strip_prefix_suffix("/api", "/api/v1"), Some("/v1"));
        assert_eq!(route_strip_prefix_suffix("/", "/api/v1"), Some("api/v1"));
        assert_eq!(route_strip_prefix_suffix("/api", "/apiv1"), None);
    }

    #[test]
    fn http_upgrade_tokens_follow_http_token_grammar() {
        assert!(http_token_valid("websocket"));
        assert!(http_token_valid("h2c"));
        assert!(http_token_valid("token!#$%&'*+-.^_`|~09AZaz"));
        assert!(http_upgrade_token_valid("websocket"));
        assert!(!http_token_valid(""));
        assert!(!http_token_valid("web socket"));
        assert!(!http_token_valid("websocket\r\nx"));
        assert!(!http_token_valid("websocket;param"));
        assert!(!http_token_valid("websocket/1"));
    }

    #[test]
    fn appends_fluxheim_via_value_to_existing_chain() {
        assert_eq!(append_fluxheim_via_value(""), "1.1 fluxheim");
        assert_eq!(append_fluxheim_via_value("   "), "1.1 fluxheim");
        assert_eq!(
            append_fluxheim_via_value(" 1.0 edge, 1.1 cache "),
            "1.0 edge, 1.1 cache, 1.1 fluxheim"
        );
    }

    #[test]
    fn response_rewrite_prefix_requires_authority_boundary_for_origin_prefixes() {
        assert!(response_rewrite_prefix_matches(
            "http://backend.internal",
            "http://backend.internal"
        ));
        assert!(response_rewrite_prefix_matches(
            "http://backend.internal/login",
            "http://backend.internal"
        ));
        assert!(response_rewrite_prefix_matches(
            "http://backend.internal?next=/",
            "http://backend.internal"
        ));
        assert!(response_rewrite_prefix_matches(
            "http://backend.internal#fragment",
            "http://backend.internal"
        ));
        assert!(!response_rewrite_prefix_matches(
            "http://backend.internal@evil.example/phish",
            "http://backend.internal"
        ));
        assert!(!response_rewrite_prefix_matches(
            "http://backend.internal.evil.example/phish",
            "http://backend.internal"
        ));
        assert!(!response_rewrite_prefix_matches(
            "http://backend.internal.evil.example/phish",
            "http://backend.internal."
        ));
        assert!(response_rewrite_prefix_matches("/old/path", "/old"));
    }
}
