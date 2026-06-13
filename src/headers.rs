use std::net::{IpAddr, SocketAddr};

#[cfg(not(feature = "privacy-mode"))]
use crate::config::{
    ForwardedClientIpHeaderMode, HeaderValues, RequestHeaderPolicyConfig,
    ResponseHeaderPolicyConfig,
};
#[cfg(feature = "privacy-mode")]
use crate::config::{HeaderValues, RequestHeaderPolicyConfig, ResponseHeaderPolicyConfig};
use crate::http_types::{
    PingoraRequestHeader as RequestHeader, PingoraResponseHeader as ResponseHeader,
};

const SPOOFABLE_CLIENT_IP_HEADERS: &[&str] = &[
    "x-forwarded-for",
    "x-real-ip",
    "forwarded",
    "cf-connecting-ip",
    "true-client-ip",
    "x-client-ip",
    "x-cluster-client-ip",
    "fastly-client-ip",
];
const DEFAULT_SERVER_HEADER: &str = "fluxheim";

pub fn apply_upstream_request_policy(
    request: &mut RequestHeader,
    policy: &RequestHeaderPolicyConfig,
    context: UpstreamRequestPolicyContext<'_>,
) -> pingora::Result<()> {
    #[cfg(feature = "privacy-mode")]
    {
        let _ = context;
        apply_privacy_upstream_request_policy(request, policy, context.request_id)
    }

    #[cfg(not(feature = "privacy-mode"))]
    {
        apply_standard_upstream_request_policy(request, policy, context)
    }
}

pub fn strip_upstream_hop_by_hop_request_headers(
    request: &mut RequestHeader,
) -> pingora::Result<()> {
    let connection_listed_headers = request
        .headers
        .get_all("connection")
        .iter()
        .flat_map(|value| value.to_str().unwrap_or_default().split(','))
        .map(str::trim)
        .filter(|value| fluxheim_protocol::http_token_valid(value))
        .map(str::to_ascii_lowercase)
        .collect::<Vec<_>>();
    let preserve_chunked_framing = request
        .headers
        .get_all("transfer-encoding")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .rfind(|value| !value.is_empty())
        .is_some_and(|coding| coding.eq_ignore_ascii_case("chunked"));

    for header in connection_listed_headers {
        request.remove_header(header.as_str());
    }

    for header in [
        "connection",
        "keep-alive",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        request.remove_header(header);
    }

    if preserve_chunked_framing {
        request.insert_header("transfer-encoding", "chunked")?;
    }

    Ok(())
}

#[derive(Clone, Copy)]
pub struct UpstreamRequestPolicyContext<'a> {
    pub client_addr: Option<&'a SocketAddr>,
    pub trusted_proxy: bool,
    pub trusted_proxy_matcher: Option<&'a dyn Fn(IpAddr) -> bool>,
    pub downstream_tls: bool,
    pub request_id: Option<&'a str>,
    pub tls_identity: Option<&'a RequestTlsClientIdentity>,
    pub route_regex_captures: Option<&'a RouteRegexCaptures>,
}

#[derive(Clone, Debug, Default)]
pub struct RequestTlsClientIdentity {
    pub cipher: Option<String>,
    pub version: Option<String>,
    pub organization: Option<String>,
    pub serial_number: Option<String>,
    pub cert_sha256: Option<String>,
}

impl RequestTlsClientIdentity {
    pub fn from_ssl_digest(digest: &pingora::protocols::tls::SslDigest) -> Self {
        Self {
            cipher: (!digest.cipher.is_empty()).then(|| digest.cipher.to_string()),
            version: (!digest.version.is_empty()).then(|| digest.version.to_string()),
            organization: digest
                .organization
                .clone()
                .filter(|value| !value.is_empty()),
            serial_number: digest
                .serial_number
                .clone()
                .filter(|value| !value.is_empty()),
            cert_sha256: (!digest.cert_digest.is_empty()).then(|| hex_lower(&digest.cert_digest)),
        }
    }
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

#[cfg(feature = "privacy-mode")]
fn apply_privacy_upstream_request_policy(
    request: &mut RequestHeader,
    policy: &RequestHeaderPolicyConfig,
    request_id: Option<&str>,
) -> pingora::Result<()> {
    if policy.enabled {
        let unset = policy.effective_unset();
        let set = policy.effective_set();
        let context =
            RequestHeaderTemplateContext::new(request, None, false, request_id, None, None);
        apply_request_mutations(request, &unset, &set, &policy.append, &context)?;
    }
    for header in SPOOFABLE_CLIENT_IP_HEADERS {
        request.remove_header(*header);
    }
    Ok(())
}

#[cfg(not(feature = "privacy-mode"))]
fn apply_standard_upstream_request_policy(
    request: &mut RequestHeader,
    policy: &RequestHeaderPolicyConfig,
    context: UpstreamRequestPolicyContext<'_>,
) -> pingora::Result<()> {
    if !policy.enabled {
        return Ok(());
    }

    let original_x_forwarded_for = request
        .headers
        .get("x-forwarded-for")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let original_host = request
        .headers
        .get("host")
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned);
    let proto = if context.downstream_tls {
        "https"
    } else {
        "http"
    };

    if policy.strip_inbound_client_ip_headers {
        for header in SPOOFABLE_CLIENT_IP_HEADERS {
            request.remove_header(*header);
        }
    }

    let effective_client_ip = context.client_addr.map(|client_addr| {
        effective_client_ip(
            client_addr.ip(),
            context.trusted_proxy,
            original_x_forwarded_for.as_deref(),
            context.trusted_proxy_matcher,
        )
    });

    if policy.x_real_ip {
        if let Some(client_ip) = effective_client_ip {
            request.insert_header("x-real-ip", client_ip.to_string())?;
        } else {
            request.remove_header("x-real-ip");
        }
    }

    if let Some(client_ip) = effective_client_ip {
        apply_x_forwarded_for(
            request,
            policy.x_forwarded_for,
            context
                .trusted_proxy
                .then_some(original_x_forwarded_for.as_deref())
                .flatten(),
            client_ip,
        )?;
    } else if matches!(policy.x_forwarded_for, ForwardedClientIpHeaderMode::Replace) {
        request.remove_header("x-forwarded-for");
    }

    if policy.x_forwarded_host {
        if let Some(host) = &original_host {
            request.insert_header("x-forwarded-host", host.as_str())?;
        } else {
            request.remove_header("x-forwarded-host");
        }
    }

    if policy.x_forwarded_proto {
        request.insert_header("x-forwarded-proto", proto)?;
    }

    if policy.forwarded
        && let Some(client_ip) = effective_client_ip
    {
        request.insert_header(
            "forwarded",
            build_forwarded_header(client_ip, original_host.as_deref(), proto),
        )?;
    }

    let unset = policy.effective_unset();
    let set = policy.effective_set();
    let context = RequestHeaderTemplateContext::new(
        request,
        effective_client_ip,
        context.downstream_tls,
        context.request_id,
        context.tls_identity,
        context.route_regex_captures,
    );
    apply_request_mutations(request, &unset, &set, &policy.append, &context)?;
    Ok(())
}

struct RequestHeaderTemplateContext {
    headers: http::HeaderMap,
    host: Option<String>,
    remote_addr: Option<String>,
    scheme: &'static str,
    uri: String,
    path: String,
    query: String,
    request_id: Option<String>,
    tls_identity: Option<RequestTlsClientIdentity>,
    route_regex_captures: Option<RouteRegexCaptures>,
}

impl RequestHeaderTemplateContext {
    fn new(
        request: &RequestHeader,
        client_ip: Option<IpAddr>,
        downstream_tls: bool,
        request_id: Option<&str>,
        tls_identity: Option<&RequestTlsClientIdentity>,
        route_regex_captures: Option<&RouteRegexCaptures>,
    ) -> Self {
        let host = request
            .headers
            .get("host")
            .and_then(|value| value.to_str().ok())
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_owned);
        let uri = request
            .uri
            .path_and_query()
            .map(|value| value.as_str().to_owned())
            .unwrap_or_else(|| request.uri.path().to_owned());
        let path = request.uri.path().to_owned();
        let query = request.uri.query().unwrap_or("").to_owned();

        Self {
            headers: request.headers.clone(),
            host,
            remote_addr: client_ip.map(|ip| ip.to_string()),
            scheme: if downstream_tls { "https" } else { "http" },
            uri,
            path,
            query,
            request_id: request_id.map(str::to_owned),
            tls_identity: tls_identity.cloned(),
            route_regex_captures: route_regex_captures.cloned(),
        }
    }

    fn variable(&self, variable: &str) -> Option<&str> {
        match variable {
            "host" => self.host.as_deref(),
            "remote_addr" => self.remote_addr.as_deref(),
            "scheme" => Some(self.scheme),
            "uri" => Some(self.uri.as_str()),
            "path" => Some(self.path.as_str()),
            "query" => Some(self.query.as_str()),
            "request_id" => self.request_id.as_deref(),
            "tls.cipher" => self
                .tls_identity
                .as_ref()
                .and_then(|identity| identity.cipher.as_deref()),
            "tls.version" => self
                .tls_identity
                .as_ref()
                .and_then(|identity| identity.version.as_deref()),
            "tls.client_cert_organization" => self
                .tls_identity
                .as_ref()
                .and_then(|identity| identity.organization.as_deref()),
            "tls.client_cert_serial" => self
                .tls_identity
                .as_ref()
                .and_then(|identity| identity.serial_number.as_deref()),
            "tls.client_cert_sha256" => self
                .tls_identity
                .as_ref()
                .and_then(|identity| identity.cert_sha256.as_deref()),
            variable => self
                .route_regex_captures
                .as_ref()
                .and_then(|captures| captures.variable(variable))
                .or_else(|| {
                    variable
                        .strip_prefix("http.")
                        .and_then(|name| self.headers.get(name))
                        .and_then(|value| value.to_str().ok())
                }),
        }
    }
}

pub fn apply_response_policy(
    response: &mut ResponseHeader,
    policy: &ResponseHeaderPolicyConfig,
) -> pingora::Result<()> {
    if !policy.enabled {
        return Ok(());
    }

    let hsts_value = policy
        .hsts
        .as_ref()
        .and_then(|hsts| hsts.header_value())
        .or_else(|| policy.strict_transport_security.clone());
    set_optional_header(response, "strict-transport-security", hsts_value.as_deref())?;
    set_optional_header(
        response,
        "content-security-policy",
        policy.content_security_policy.as_deref(),
    )?;
    set_optional_header(
        response,
        "x-content-type-options",
        policy.x_content_type_options.as_deref(),
    )?;
    set_optional_header(
        response,
        "x-frame-options",
        policy.x_frame_options.as_deref(),
    )?;
    set_optional_header(
        response,
        "referrer-policy",
        policy.referrer_policy.as_deref(),
    )?;
    response.insert_header("server", DEFAULT_SERVER_HEADER)?;

    let unset = policy.effective_unset();
    let set = policy.effective_set();
    apply_response_mutations(response, &unset, &set, &policy.append)?;
    apply_response_rewrites(response, &policy.rewrite)?;
    Ok(())
}

fn apply_request_mutations(
    request: &mut RequestHeader,
    unset: &[String],
    set: &std::collections::BTreeMap<String, String>,
    append: &std::collections::BTreeMap<String, HeaderValues>,
    context: &RequestHeaderTemplateContext,
) -> pingora::Result<()> {
    for name in unset {
        request.remove_header(name.as_str());
    }
    for (name, value) in set {
        request.remove_header(name.as_str());
        let value = render_header_template(value, context);
        if !value.is_empty() {
            request.insert_header(name.clone(), value)?;
        }
    }
    for (name, values) in append {
        for value in values.iter() {
            let value = render_header_template(value, context);
            if !value.is_empty() {
                request.append_header(name.clone(), value)?;
            }
        }
    }

    Ok(())
}

fn render_header_template(value: &str, context: &RequestHeaderTemplateContext) -> String {
    let mut rendered = String::with_capacity(value.len());
    let mut rest = value;

    while let Some(open) = rest.find('{') {
        rendered.push_str(&rest[..open]);
        let after_open = &rest[open + 1..];
        let Some(close) = after_open.find('}') else {
            rendered.push_str(&rest[open..]);
            return rendered;
        };
        let variable = &after_open[..close];
        if let Some(value) = context.variable(variable) {
            push_header_template_variable(&mut rendered, value);
        }
        rest = &after_open[close + 1..];
    }

    rendered.push_str(rest);
    rendered
}

fn push_header_template_variable(rendered: &mut String, value: &str) {
    rendered.extend(value.chars().filter(|character| !character.is_control()));
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len().saturating_mul(2));
    for byte in bytes {
        encoded.push(HEX[(byte >> 4) as usize] as char);
        encoded.push(HEX[(byte & 0x0f) as usize] as char);
    }
    encoded
}

fn apply_response_mutations(
    response: &mut ResponseHeader,
    unset: &[String],
    set: &std::collections::BTreeMap<String, String>,
    append: &std::collections::BTreeMap<String, HeaderValues>,
) -> pingora::Result<()> {
    for name in unset {
        response.remove_header(name.as_str());
    }
    for (name, value) in set {
        response.remove_header(name.as_str());
        response.insert_header(name.clone(), value.as_str())?;
    }
    for (name, values) in append {
        for value in values.iter() {
            response.append_header(name.clone(), value)?;
        }
    }

    Ok(())
}

fn apply_response_rewrites(
    response: &mut ResponseHeader,
    rewrite: &crate::config::ResponseHeaderRewriteConfig,
) -> pingora::Result<()> {
    rewrite_header_values(
        response,
        "location",
        &rewrite.location,
        rewrite_header_prefix,
    )?;
    rewrite_header_values(response, "refresh", &rewrite.refresh, rewrite_refresh_url)?;
    rewrite_set_cookie_values(response, rewrite)
}

fn rewrite_header_values(
    response: &mut ResponseHeader,
    name: &'static str,
    rules: &[crate::config::ResponseHeaderRewriteRuleConfig],
    rewrite_value: fn(&str, &[crate::config::ResponseHeaderRewriteRuleConfig]) -> Option<String>,
) -> pingora::Result<()> {
    if rules.is_empty() {
        return Ok(());
    }

    let values = response
        .headers
        .get_all(name)
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    if values.is_empty() {
        return Ok(());
    }

    let mut rewritten = Vec::with_capacity(values.len());
    let mut changed = false;
    for value in values {
        if let Ok(text) = value.to_str()
            && let Some(next) = rewrite_value(text, rules)
        {
            rewritten.push(RewrittenResponseHeaderValue::Text(next));
            changed = true;
            continue;
        }
        rewritten.push(RewrittenResponseHeaderValue::Original(value));
    }

    if changed {
        response.remove_header(name);
        for value in rewritten {
            match value {
                RewrittenResponseHeaderValue::Original(value) => {
                    response.append_header(name, value)?;
                }
                RewrittenResponseHeaderValue::Text(value) => {
                    response.append_header(name, value.as_str())?;
                }
            }
        }
    }

    Ok(())
}

enum RewrittenResponseHeaderValue {
    Original(http::HeaderValue),
    Text(String),
}

fn rewrite_header_prefix(
    value: &str,
    rules: &[crate::config::ResponseHeaderRewriteRuleConfig],
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

fn rewrite_refresh_url(
    value: &str,
    rules: &[crate::config::ResponseHeaderRewriteRuleConfig],
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

fn rewrite_set_cookie_values(
    response: &mut ResponseHeader,
    rewrite: &crate::config::ResponseHeaderRewriteConfig,
) -> pingora::Result<()> {
    if rewrite.cookie_domain.is_empty() && rewrite.cookie_path.is_empty() {
        return Ok(());
    }

    let values = response
        .headers
        .get_all("set-cookie")
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    if values.is_empty() {
        return Ok(());
    }

    let mut rewritten = Vec::with_capacity(values.len());
    let mut changed = false;
    for value in values {
        if let Ok(text) = value.to_str()
            && let Some(next) = rewrite_set_cookie_value(text, rewrite)
        {
            rewritten.push(RewrittenResponseHeaderValue::Text(next));
            changed = true;
            continue;
        }
        rewritten.push(RewrittenResponseHeaderValue::Original(value));
    }

    if changed {
        response.remove_header("set-cookie");
        for value in rewritten {
            match value {
                RewrittenResponseHeaderValue::Original(value) => {
                    response.append_header("set-cookie", value)?;
                }
                RewrittenResponseHeaderValue::Text(value) => {
                    response.append_header("set-cookie", value.as_str())?;
                }
            }
        }
    }

    Ok(())
}

fn rewrite_set_cookie_value(
    value: &str,
    rewrite: &crate::config::ResponseHeaderRewriteConfig,
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
    rules: &[crate::config::ResponseHeaderRewriteRuleConfig],
    rewrite_value: fn(
        CookieAttributeValue<'_>,
        &[crate::config::ResponseHeaderRewriteRuleConfig],
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
    rules: &[crate::config::ResponseHeaderRewriteRuleConfig],
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
    rules: &[crate::config::ResponseHeaderRewriteRuleConfig],
) -> Option<String> {
    rewrite_header_prefix(value.normalized, rules)
}

#[cfg(not(feature = "privacy-mode"))]
fn apply_x_forwarded_for(
    request: &mut RequestHeader,
    mode: ForwardedClientIpHeaderMode,
    original_value: Option<&str>,
    client_ip: IpAddr,
) -> pingora::Result<()> {
    match mode {
        ForwardedClientIpHeaderMode::Off => {
            request.remove_header("x-forwarded-for");
        }
        ForwardedClientIpHeaderMode::Replace => {
            request.insert_header("x-forwarded-for", client_ip.to_string())?;
        }
        ForwardedClientIpHeaderMode::Append => {
            let value = match original_value {
                Some(original_value) => format!("{original_value}, {client_ip}"),
                None => client_ip.to_string(),
            };
            request.insert_header("x-forwarded-for", value)?;
        }
    }

    Ok(())
}

#[cfg(not(feature = "privacy-mode"))]
fn effective_client_ip(
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

#[cfg(not(feature = "privacy-mode"))]
fn parse_x_forwarded_for_ip(value: &str) -> Option<IpAddr> {
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

#[cfg(not(feature = "privacy-mode"))]
fn build_forwarded_header(client_ip: IpAddr, host: Option<&str>, proto: &str) -> String {
    let mut value = format!("for={}", forwarded_ip(client_ip));
    if let Some(host) = host {
        value.push_str(";host=");
        value.push_str(&quote_forwarded_value(host));
    }
    value.push_str(";proto=");
    value.push_str(proto);
    value
}

#[cfg(not(feature = "privacy-mode"))]
fn forwarded_ip(client_ip: IpAddr) -> String {
    match client_ip {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("\"[{ip}]\""),
    }
}

#[cfg(not(feature = "privacy-mode"))]
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

fn set_optional_header(
    response: &mut ResponseHeader,
    name: &'static str,
    value: Option<&str>,
) -> pingora::Result<()> {
    let Some(value) = value else {
        return Ok(());
    };

    response.remove_header(name);
    response.insert_header(name, value)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[cfg(not(feature = "privacy-mode"))]
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
    #[cfg(feature = "privacy-mode")]
    use std::net::{Ipv4Addr, SocketAddr};

    use super::{
        CookieAttributeValue, RequestHeader, ResponseHeader, UpstreamRequestPolicyContext,
        apply_response_policy, apply_upstream_request_policy, rewrite_cookie_domain,
        strip_upstream_hop_by_hop_request_headers,
    };
    #[cfg(not(feature = "privacy-mode"))]
    use super::{
        RequestHeaderTemplateContext, RequestTlsClientIdentity, RouteRegexCaptures,
        render_header_template,
    };
    #[cfg(not(feature = "privacy-mode"))]
    use proptest::prelude::*;

    #[cfg(not(feature = "privacy-mode"))]
    fn test_upstream_context<'a>(
        client_addr: &'a SocketAddr,
        trusted_proxy: bool,
        trusted_proxy_matcher: Option<&'a dyn Fn(IpAddr) -> bool>,
        downstream_tls: bool,
        request_id: Option<&'a str>,
        tls_identity: Option<&'a RequestTlsClientIdentity>,
    ) -> UpstreamRequestPolicyContext<'a> {
        UpstreamRequestPolicyContext {
            client_addr: Some(client_addr),
            trusted_proxy,
            trusted_proxy_matcher,
            downstream_tls,
            request_id,
            tls_identity,
            route_regex_captures: None,
        }
    }

    #[test]
    fn applies_default_response_headers() {
        let policy = crate::config::ResponseHeaderPolicyConfig::default();
        let mut response = ResponseHeader::build(200, None).unwrap();
        response.insert_header("server", "origin/1.2.3").unwrap();
        response.insert_header("x-powered-by", "framework").unwrap();

        apply_response_policy(&mut response, &policy).unwrap();

        assert_eq!(
            response
                .headers
                .get("server")
                .and_then(|value| value.to_str().ok()),
            Some("fluxheim")
        );
        assert!(response.headers.get("x-powered-by").is_none());
        assert_eq!(
            response
                .headers
                .get("x-content-type-options")
                .and_then(|value| value.to_str().ok()),
            Some("nosniff")
        );
        assert_eq!(
            response
                .headers
                .get("x-frame-options")
                .and_then(|value| value.to_str().ok()),
            Some("DENY")
        );
        assert_eq!(
            response
                .headers
                .get("referrer-policy")
                .and_then(|value| value.to_str().ok()),
            Some("no-referrer")
        );
    }

    #[test]
    fn disabled_policy_does_not_modify_response() {
        let policy = crate::config::ResponseHeaderPolicyConfig {
            enabled: false,
            ..crate::config::ResponseHeaderPolicyConfig::default()
        };
        let mut response = ResponseHeader::build(200, None).unwrap();

        apply_response_policy(&mut response, &policy).unwrap();

        assert!(response.headers.get("x-content-type-options").is_none());
        assert!(response.headers.get("x-frame-options").is_none());
        assert!(response.headers.get("referrer-policy").is_none());
    }

    #[test]
    fn applies_response_header_mutations_after_defaults() {
        let policy = crate::config::ResponseHeaderPolicyConfig {
            unset: vec!["x-frame-options".to_owned(), "server".to_owned()],
            set: std::collections::BTreeMap::from([
                ("cache-control".to_owned(), "public, max-age=60".to_owned()),
                ("access-control-allow-origin".to_owned(), "*".to_owned()),
            ]),
            append: std::collections::BTreeMap::from([
                (
                    "vary".to_owned(),
                    crate::config::HeaderValues::Many(vec![
                        "Accept-Encoding".to_owned(),
                        "Origin".to_owned(),
                    ]),
                ),
                (
                    "set-cookie".to_owned(),
                    crate::config::HeaderValues::One(
                        "fluxheim=1; HttpOnly; Secure; SameSite=Lax".to_owned(),
                    ),
                ),
            ]),
            ..crate::config::ResponseHeaderPolicyConfig::default()
        };
        let mut response = ResponseHeader::build(200, None).unwrap();
        response.insert_header("server", "origin-version").unwrap();

        apply_response_policy(&mut response, &policy).unwrap();

        assert!(response.headers.get("server").is_none());
        assert!(response.headers.get("x-frame-options").is_none());
        assert_eq!(
            response
                .headers
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("public, max-age=60")
        );
        assert_eq!(
            response
                .headers
                .get_all("vary")
                .iter()
                .filter_map(|value| value.to_str().ok())
                .collect::<Vec<_>>(),
            ["Accept-Encoding", "Origin"]
        );
        assert_eq!(
            response
                .headers
                .get("set-cookie")
                .and_then(|value| value.to_str().ok()),
            Some("fluxheim=1; HttpOnly; Secure; SameSite=Lax")
        );
    }

    #[test]
    fn applies_user_friendly_response_header_operations() {
        let policy = crate::config::ResponseHeaderPolicyConfig {
            remove: vec!["x-origin-banner".to_owned()],
            add: std::collections::BTreeMap::from([(
                "cache-control".to_owned(),
                "public, max-age=300".to_owned(),
            )]),
            operations: crate::config::HeaderOperationsConfig {
                remove: vec!["x-debug".to_owned()],
                add: std::collections::BTreeMap::from([(
                    "x-content-source".to_owned(),
                    "fluxheim".to_owned(),
                )]),
            },
            ..crate::config::ResponseHeaderPolicyConfig::default()
        };
        let mut response = ResponseHeader::build(200, None).unwrap();
        response.insert_header("x-origin-banner", "origin").unwrap();
        response.insert_header("x-debug", "1").unwrap();

        apply_response_policy(&mut response, &policy).unwrap();

        assert!(response.headers.get("x-origin-banner").is_none());
        assert!(response.headers.get("x-debug").is_none());
        assert_eq!(
            response
                .headers
                .get("cache-control")
                .and_then(|value| value.to_str().ok()),
            Some("public, max-age=300")
        );
        assert_eq!(
            response
                .headers
                .get("x-content-source")
                .and_then(|value| value.to_str().ok()),
            Some("fluxheim")
        );
    }

    #[test]
    fn explicit_response_server_header_can_override_default_unset() {
        let policy = crate::config::ResponseHeaderPolicyConfig {
            set: std::collections::BTreeMap::from([("server".to_owned(), "Fluxheim".to_owned())]),
            ..crate::config::ResponseHeaderPolicyConfig::default()
        };
        let mut response = ResponseHeader::build(200, None).unwrap();
        response.insert_header("server", "origin-version").unwrap();

        apply_response_policy(&mut response, &policy).unwrap();

        assert_eq!(
            response
                .headers
                .get("server")
                .and_then(|value| value.to_str().ok()),
            Some("Fluxheim")
        );
    }

    #[test]
    fn rewrites_response_location_and_refresh_headers() {
        let policy = crate::config::ResponseHeaderPolicyConfig {
            rewrite: crate::config::ResponseHeaderRewriteConfig {
                location: vec![crate::config::ResponseHeaderRewriteRuleConfig {
                    from: "http://backend.internal/".to_owned(),
                    to: "https://example.test/".to_owned(),
                }],
                refresh: vec![crate::config::ResponseHeaderRewriteRuleConfig {
                    from: "http://backend.internal/".to_owned(),
                    to: "https://example.test/".to_owned(),
                }],
                ..crate::config::ResponseHeaderRewriteConfig::default()
            },
            ..crate::config::ResponseHeaderPolicyConfig::default()
        };
        let mut response = ResponseHeader::build(302, None).unwrap();
        response
            .insert_header("location", "http://backend.internal/login?next=/admin")
            .unwrap();
        response
            .insert_header("refresh", "0; url = http://backend.internal/login")
            .unwrap();

        apply_response_policy(&mut response, &policy).unwrap();

        assert_eq!(
            response
                .headers
                .get("location")
                .and_then(|value| value.to_str().ok()),
            Some("https://example.test/login?next=/admin")
        );
        assert_eq!(
            response
                .headers
                .get("refresh")
                .and_then(|value| value.to_str().ok()),
            Some("0; url = https://example.test/login")
        );
    }

    #[test]
    fn response_location_rewrite_rejects_absolute_authority_continuations() {
        let policy = crate::config::ResponseHeaderPolicyConfig {
            rewrite: crate::config::ResponseHeaderRewriteConfig {
                location: vec![crate::config::ResponseHeaderRewriteRuleConfig {
                    from: "http://backend.internal".to_owned(),
                    to: "https://example.test".to_owned(),
                }],
                ..crate::config::ResponseHeaderRewriteConfig::default()
            },
            ..crate::config::ResponseHeaderPolicyConfig::default()
        };
        let mut rejected = ResponseHeader::build(302, None).unwrap();
        rejected
            .insert_header("location", "http://backend.internal@evil.example/phish")
            .unwrap();
        let mut allowed = ResponseHeader::build(302, None).unwrap();
        allowed
            .insert_header("location", "http://backend.internal/login")
            .unwrap();

        apply_response_policy(&mut rejected, &policy).unwrap();
        apply_response_policy(&mut allowed, &policy).unwrap();

        assert_eq!(
            rejected
                .headers
                .get("location")
                .and_then(|value| value.to_str().ok()),
            Some("http://backend.internal@evil.example/phish")
        );
        assert_eq!(
            allowed
                .headers
                .get("location")
                .and_then(|value| value.to_str().ok()),
            Some("https://example.test/login")
        );
    }

    #[test]
    fn rewrites_quoted_response_refresh_urls() {
        let policy = crate::config::ResponseHeaderPolicyConfig {
            rewrite: crate::config::ResponseHeaderRewriteConfig {
                refresh: vec![crate::config::ResponseHeaderRewriteRuleConfig {
                    from: "http://backend.internal/".to_owned(),
                    to: "https://example.test/".to_owned(),
                }],
                ..crate::config::ResponseHeaderRewriteConfig::default()
            },
            ..crate::config::ResponseHeaderPolicyConfig::default()
        };
        let mut response = ResponseHeader::build(200, None).unwrap();
        response
            .append_header("refresh", "0; url=\"http://backend.internal/login\"")
            .unwrap();
        response
            .append_header("refresh", "0; url='http://backend.internal/admin'")
            .unwrap();

        apply_response_policy(&mut response, &policy).unwrap();

        assert_eq!(
            response
                .headers
                .get_all("refresh")
                .iter()
                .filter_map(|value| value.to_str().ok())
                .collect::<Vec<_>>(),
            [
                "0; url=\"https://example.test/login\"",
                "0; url='https://example.test/admin'"
            ]
        );
    }

    #[test]
    fn response_header_rewrite_preserves_non_matching_values() {
        let policy = crate::config::ResponseHeaderPolicyConfig {
            rewrite: crate::config::ResponseHeaderRewriteConfig {
                location: vec![crate::config::ResponseHeaderRewriteRuleConfig {
                    from: "http://backend.internal/".to_owned(),
                    to: "https://example.test/".to_owned(),
                }],
                refresh: Vec::new(),
                ..crate::config::ResponseHeaderRewriteConfig::default()
            },
            ..crate::config::ResponseHeaderPolicyConfig::default()
        };
        let mut response = ResponseHeader::build(302, None).unwrap();
        response
            .insert_header("location", "https://other.example/login")
            .unwrap();

        apply_response_policy(&mut response, &policy).unwrap();

        assert_eq!(
            response
                .headers
                .get("location")
                .and_then(|value| value.to_str().ok()),
            Some("https://other.example/login")
        );
    }

    #[test]
    fn rewrites_set_cookie_domain_and_path_attributes() {
        let policy = crate::config::ResponseHeaderPolicyConfig {
            rewrite: crate::config::ResponseHeaderRewriteConfig {
                cookie_domain: vec![crate::config::ResponseHeaderRewriteRuleConfig {
                    from: "backend.internal".to_owned(),
                    to: "example.test".to_owned(),
                }],
                cookie_path: vec![crate::config::ResponseHeaderRewriteRuleConfig {
                    from: "/app/".to_owned(),
                    to: "/".to_owned(),
                }],
                ..crate::config::ResponseHeaderRewriteConfig::default()
            },
            ..crate::config::ResponseHeaderPolicyConfig::default()
        };
        let mut response = ResponseHeader::build(200, None).unwrap();
        response
            .append_header(
                "set-cookie",
                "session=abc; Domain=BACKEND.internal; Path=/app/admin; HttpOnly",
            )
            .unwrap();
        response
            .append_header(
                "set-cookie",
                "leading=1; Domain=.backend.internal; Path=/; HttpOnly",
            )
            .unwrap();
        response
            .append_header(
                "set-cookie",
                "quoted=1; Domain=\"backend.internal\"; Path=\"/app/admin\"; HttpOnly",
            )
            .unwrap();
        response
            .append_header(
                "set-cookie",
                "spaced=1; Domain=backend.internal \t; Path=/app/admin \t; HttpOnly",
            )
            .unwrap();
        response
            .append_header("set-cookie", "theme=dark; Path=/public; Secure")
            .unwrap();

        apply_response_policy(&mut response, &policy).unwrap();

        assert_eq!(
            response
                .headers
                .get_all("set-cookie")
                .iter()
                .filter_map(|value| value.to_str().ok())
                .collect::<Vec<_>>(),
            [
                "session=abc; Domain=example.test; Path=/admin; HttpOnly",
                "leading=1; Domain=example.test; Path=/; HttpOnly",
                "quoted=1; Domain=example.test; Path=/admin; HttpOnly",
                "spaced=1; Domain=example.test; Path=/admin; HttpOnly",
                "theme=dark; Path=/public; Secure"
            ]
        );
    }

    #[test]
    fn cookie_domain_rewrite_matches_symmetric_leading_dot_rules() {
        let rules = [crate::config::ResponseHeaderRewriteRuleConfig {
            from: ".backend.internal".to_owned(),
            to: "example.test".to_owned(),
        }];

        assert_eq!(
            rewrite_cookie_domain(CookieAttributeValue::new("backend.internal"), &rules),
            Some("example.test".to_owned())
        );
        assert_eq!(
            rewrite_cookie_domain(CookieAttributeValue::new(".BACKEND.internal"), &rules),
            Some("example.test".to_owned())
        );
    }

    #[test]
    fn strips_upstream_hop_by_hop_request_headers() {
        let mut request = RequestHeader::build("GET", b"/", None).unwrap();
        request
            .insert_header("connection", "close, x-hop, keep-alive")
            .unwrap();
        request.insert_header("x-hop", "remove").unwrap();
        request.insert_header("keep-alive", "timeout=9999").unwrap();
        request
            .insert_header("proxy-authorization", "Basic dGVzdA==")
            .unwrap();
        request
            .insert_header("proxy-authenticate", "Basic realm=test")
            .unwrap();
        request.insert_header("te", "trailers").unwrap();
        request.insert_header("trailer", "x-extra").unwrap();
        request.insert_header("upgrade", "h2c").unwrap();
        request.insert_header("x-end-to-end", "keep").unwrap();

        strip_upstream_hop_by_hop_request_headers(&mut request).unwrap();

        for header in [
            "connection",
            "x-hop",
            "keep-alive",
            "proxy-authorization",
            "proxy-authenticate",
            "te",
            "trailer",
            "upgrade",
        ] {
            assert!(request.headers.get(header).is_none(), "{header}");
        }
        assert_eq!(
            request
                .headers
                .get("x-end-to-end")
                .and_then(|value| value.to_str().ok()),
            Some("keep")
        );
    }

    #[test]
    fn normalizes_upstream_chunked_transfer_encoding_for_body_framing() {
        let mut request = RequestHeader::build("POST", b"/upload", None).unwrap();
        request
            .insert_header("transfer-encoding", "gzip, chunked")
            .unwrap();

        strip_upstream_hop_by_hop_request_headers(&mut request).unwrap();

        assert_eq!(
            request
                .headers
                .get("transfer-encoding")
                .and_then(|value| value.to_str().ok()),
            Some("chunked")
        );
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn applies_default_upstream_request_headers() {
        let policy = crate::config::RequestHeaderPolicyConfig::default();
        let mut request = RequestHeader::build("GET", b"/", Some(8)).unwrap();
        request.insert_header("host", "example.test").unwrap();
        request
            .insert_header("x-forwarded-for", "198.51.100.9")
            .unwrap();
        request.insert_header("x-real-ip", "198.51.100.9").unwrap();
        let client_addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 53210));

        apply_upstream_request_policy(
            &mut request,
            &policy,
            test_upstream_context(&client_addr, false, None, true, None, None),
        )
        .unwrap();

        assert_eq!(
            request
                .headers
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok()),
            Some("203.0.113.10")
        );
        assert!(request.headers.get("x-real-ip").is_none());
        assert_eq!(
            request
                .headers
                .get("x-forwarded-host")
                .and_then(|value| value.to_str().ok()),
            Some("example.test")
        );
        assert_eq!(
            request
                .headers
                .get("x-forwarded-proto")
                .and_then(|value| value.to_str().ok()),
            Some("https")
        );
        assert!(request.headers.get("forwarded").is_none());
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn can_emit_x_real_ip_when_enabled() {
        let policy = crate::config::RequestHeaderPolicyConfig {
            x_real_ip: true,
            ..crate::config::RequestHeaderPolicyConfig::default()
        };
        let mut request = RequestHeader::build("GET", b"/", Some(8)).unwrap();
        request.insert_header("host", "example.test").unwrap();
        let client_addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 53210));

        apply_upstream_request_policy(
            &mut request,
            &policy,
            test_upstream_context(&client_addr, false, None, true, None, None),
        )
        .unwrap();

        assert_eq!(
            request
                .headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok()),
            Some("203.0.113.10")
        );
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn applies_request_header_mutations_after_forwarding_defaults() {
        let policy = crate::config::RequestHeaderPolicyConfig {
            unset: vec!["x-forwarded-proto".to_owned(), "x-powered-by".to_owned()],
            set: std::collections::BTreeMap::from([
                ("host".to_owned(), "backend.internal".to_owned()),
                ("x-proxy-by".to_owned(), "Fluxheim".to_owned()),
            ]),
            append: std::collections::BTreeMap::from([(
                "via".to_owned(),
                crate::config::HeaderValues::One("fluxheim".to_owned()),
            )]),
            ..crate::config::RequestHeaderPolicyConfig::default()
        };
        let mut request = RequestHeader::build("GET", b"/", Some(8)).unwrap();
        request.insert_header("host", "example.test").unwrap();
        request
            .insert_header("x-powered-by", "origin-version")
            .unwrap();
        let client_addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 53210));

        apply_upstream_request_policy(
            &mut request,
            &policy,
            test_upstream_context(&client_addr, false, None, true, None, None),
        )
        .unwrap();

        assert_eq!(
            request
                .headers
                .get("host")
                .and_then(|value| value.to_str().ok()),
            Some("backend.internal")
        );
        assert_eq!(
            request
                .headers
                .get("x-proxy-by")
                .and_then(|value| value.to_str().ok()),
            Some("Fluxheim")
        );
        assert!(request.headers.get("x-forwarded-proto").is_none());
        assert!(request.headers.get("x-powered-by").is_none());
        assert_eq!(
            request
                .headers
                .get("via")
                .and_then(|value| value.to_str().ok()),
            Some("fluxheim")
        );
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn renders_safe_dynamic_request_header_values() {
        let policy = crate::config::RequestHeaderPolicyConfig {
            set: std::collections::BTreeMap::from([
                ("host".to_owned(), "{host}".to_owned()),
                ("x-real-ip".to_owned(), "{remote_addr}".to_owned()),
                ("x-forwarded-proto".to_owned(), "{scheme}".to_owned()),
                ("x-original-uri".to_owned(), "{uri}".to_owned()),
                ("x-original-path".to_owned(), "{path}".to_owned()),
                ("x-original-query".to_owned(), "{query}".to_owned()),
                ("x-request-id".to_owned(), "{request_id}".to_owned()),
                (
                    "x-client-cert-sha256".to_owned(),
                    "{tls.client_cert_sha256}".to_owned(),
                ),
                (
                    "x-client-cert-serial".to_owned(),
                    "{tls.client_cert_serial}".to_owned(),
                ),
                ("x-tls-version".to_owned(), "{tls.version}".to_owned()),
                ("upgrade".to_owned(), "{http.upgrade}".to_owned()),
            ]),
            ..crate::config::RequestHeaderPolicyConfig::default()
        };
        let mut request = RequestHeader::build("GET", b"/chat/?room=main", Some(8)).unwrap();
        request.insert_header("host", "example.test").unwrap();
        request.insert_header("upgrade", "websocket").unwrap();
        let client_addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 53210));
        let tls_identity = RequestTlsClientIdentity {
            version: Some("TLSv1.3".to_owned()),
            serial_number: Some("01AB".to_owned()),
            cert_sha256: Some("aabbcc".to_owned()),
            ..RequestTlsClientIdentity::default()
        };

        apply_upstream_request_policy(
            &mut request,
            &policy,
            test_upstream_context(
                &client_addr,
                false,
                None,
                true,
                Some("req-123"),
                Some(&tls_identity),
            ),
        )
        .unwrap();

        assert_eq!(
            request
                .headers
                .get("host")
                .and_then(|value| value.to_str().ok()),
            Some("example.test")
        );
        assert_eq!(
            request
                .headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok()),
            Some("203.0.113.10")
        );
        assert_eq!(
            request
                .headers
                .get("x-forwarded-proto")
                .and_then(|value| value.to_str().ok()),
            Some("https")
        );
        assert_eq!(
            request
                .headers
                .get("x-original-uri")
                .and_then(|value| value.to_str().ok()),
            Some("/chat/?room=main")
        );
        assert_eq!(
            request
                .headers
                .get("x-original-path")
                .and_then(|value| value.to_str().ok()),
            Some("/chat/")
        );
        assert_eq!(
            request
                .headers
                .get("x-original-query")
                .and_then(|value| value.to_str().ok()),
            Some("room=main")
        );
        assert_eq!(
            request
                .headers
                .get("x-request-id")
                .and_then(|value| value.to_str().ok()),
            Some("req-123")
        );
        assert_eq!(
            request
                .headers
                .get("x-client-cert-sha256")
                .and_then(|value| value.to_str().ok()),
            Some("aabbcc")
        );
        assert_eq!(
            request
                .headers
                .get("x-client-cert-serial")
                .and_then(|value| value.to_str().ok()),
            Some("01AB")
        );
        assert_eq!(
            request
                .headers
                .get("x-tls-version")
                .and_then(|value| value.to_str().ok()),
            Some("TLSv1.3")
        );
        assert_eq!(
            request
                .headers
                .get("upgrade")
                .and_then(|value| value.to_str().ok()),
            Some("websocket")
        );
    }

    #[cfg(not(feature = "privacy-mode"))]
    fn safe_header_template_fragment() -> impl Strategy<Value = String> {
        prop::string::string_regex("[A-Za-z0-9 _./:;=,?&-]{0,48}")
            .expect("valid safe header template fragment regex")
    }

    #[cfg(not(feature = "privacy-mode"))]
    fn safe_dynamic_header_context() -> RequestHeaderTemplateContext {
        let mut request = RequestHeader::build("GET", b"/chat/?room=main", Some(8)).unwrap();
        request.insert_header("host", "example.test").unwrap();
        request.insert_header("upgrade", "websocket").unwrap();

        RequestHeaderTemplateContext::new(
            &request,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
            true,
            Some("req-123"),
            Some(&RequestTlsClientIdentity {
                cipher: Some("TLS_AES_128_GCM_SHA256".to_owned()),
                version: Some("TLSv1.3".to_owned()),
                organization: Some("Fluxheim Test".to_owned()),
                serial_number: Some("01AB".to_owned()),
                cert_sha256: Some("aabbcc".to_owned()),
            }),
            None,
        )
    }

    #[cfg(not(feature = "privacy-mode"))]
    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        #[test]
        fn dynamic_header_rendering_preserves_safe_header_values(
            prefix in safe_header_template_fragment(),
            middle in safe_header_template_fragment(),
            suffix in safe_header_template_fragment(),
        ) {
            let template = format!(
                "{prefix}{{host}}{middle}{{remote_addr}}{{scheme}}{{uri}}{{path}}{{query}}{{request_id}}{{tls.client_cert_sha256}}{{tls.client_cert_serial}}{{tls.version}}{{http.upgrade}}{suffix}"
            );
            let rendered = render_header_template(&template, &safe_dynamic_header_context());

            prop_assert!(!rendered.is_empty());
            prop_assert!(rendered.bytes().all(|byte| !matches!(byte, 0x00..=0x1f | 0x7f)));
            prop_assert!(rendered.contains("example.test"));
            prop_assert!(rendered.contains("203.0.113.10"));
            prop_assert!(rendered.contains("https"));
            prop_assert!(rendered.contains("req-123"));
            prop_assert!(rendered.contains("aabbcc"));
            prop_assert!(rendered.contains("01AB"));
            prop_assert!(rendered.contains("TLSv1.3"));
            prop_assert!(rendered.contains("websocket"));
        }

        #[test]
        fn unmatched_dynamic_header_template_opening_brace_is_preserved(
            prefix in safe_header_template_fragment(),
            suffix in safe_header_template_fragment(),
        ) {
            let template = format!("{prefix}{{{suffix}");

            prop_assert_eq!(
                render_header_template(&template, &safe_dynamic_header_context()),
                template
            );
        }
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn dynamic_header_rendering_strips_control_characters_from_variables() {
        let context = RequestHeaderTemplateContext {
            headers: ::http::HeaderMap::new(),
            host: Some("example.test".to_owned()),
            remote_addr: Some("203.0.113.10\r\nx-injected: true".to_owned()),
            scheme: "https",
            uri: "/chat/\r\nbad".to_owned(),
            path: "/chat/\u{7f}bad".to_owned(),
            query: "room=main\tadmin=false".to_owned(),
            request_id: Some("req-123\nbad".to_owned()),
            tls_identity: Some(RequestTlsClientIdentity {
                serial_number: Some("01\nAB".to_owned()),
                cert_sha256: Some("aa\tbb".to_owned()),
                ..RequestTlsClientIdentity::default()
            }),
            route_regex_captures: None,
        };

        let rendered = render_header_template(
            "{host} {remote_addr} {scheme} {uri} {path} {query} {request_id} {tls.client_cert_serial} {tls.client_cert_sha256}",
            &context,
        );

        assert_eq!(
            rendered,
            "example.test 203.0.113.10x-injected: true https /chat/bad /chat/bad room=mainadmin=false req-123bad 01AB aabb"
        );
        assert!(
            rendered
                .bytes()
                .all(|byte| !matches!(byte, 0x00..=0x1f | 0x7f))
        );
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn dynamic_header_rendering_supports_route_regex_captures() {
        let mut named = std::collections::BTreeMap::new();
        named.insert("version".to_owned(), "2".to_owned());
        let captures = RouteRegexCaptures::new(
            vec![
                Some("/api/v2/users".to_owned()),
                Some("2".to_owned()),
                Some("users".to_owned()),
            ],
            named,
        );
        let mut request = RequestHeader::build("GET", b"/api/v2/users", Some(8)).unwrap();
        request.insert_header("host", "example.test").unwrap();
        let context = RequestHeaderTemplateContext::new(
            &request,
            Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10))),
            true,
            Some("req-123"),
            None,
            Some(&captures),
        );

        assert_eq!(
            render_header_template(
                "{route.regex.0} {route.regex.1} {route.regex.2} {route.regex.version} {route.regex.missing}",
                &context,
            ),
            "/api/v2/users 2 users 2 "
        );
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn applies_user_friendly_request_header_operations() {
        let policy = crate::config::RequestHeaderPolicyConfig {
            remove: vec!["x-powered-by".to_owned()],
            add: std::collections::BTreeMap::from([(
                "x-internal-route".to_owned(),
                "true".to_owned(),
            )]),
            operations: crate::config::HeaderOperationsConfig {
                remove: vec!["x-debug".to_owned()],
                add: std::collections::BTreeMap::from([(
                    "x-extra-route".to_owned(),
                    "edge".to_owned(),
                )]),
            },
            ..crate::config::RequestHeaderPolicyConfig::default()
        };
        let mut request = RequestHeader::build("GET", b"/", Some(8)).unwrap();
        request.insert_header("host", "example.test").unwrap();
        request
            .insert_header("x-powered-by", "origin-version")
            .unwrap();
        request.insert_header("x-debug", "1").unwrap();
        let client_addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 53210));

        apply_upstream_request_policy(
            &mut request,
            &policy,
            test_upstream_context(&client_addr, false, None, true, None, None),
        )
        .unwrap();

        assert!(request.headers.get("x-powered-by").is_none());
        assert!(request.headers.get("x-debug").is_none());
        assert_eq!(
            request
                .headers
                .get("x-internal-route")
                .and_then(|value| value.to_str().ok()),
            Some("true")
        );
        assert_eq!(
            request
                .headers
                .get("x-extra-route")
                .and_then(|value| value.to_str().ok()),
            Some("edge")
        );
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn preserves_upgrade_headers_by_default() {
        let policy = crate::config::RequestHeaderPolicyConfig::default();
        let mut request = RequestHeader::build("GET", b"/chat/room", Some(8)).unwrap();
        request.insert_header("host", "example.test").unwrap();
        request
            .insert_header("connection", "keep-alive, Upgrade")
            .unwrap();
        request.insert_header("upgrade", "websocket").unwrap();
        let client_addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 53210));

        apply_upstream_request_policy(
            &mut request,
            &policy,
            test_upstream_context(&client_addr, false, None, true, None, None),
        )
        .unwrap();

        assert_eq!(
            request
                .headers
                .get("connection")
                .and_then(|value| value.to_str().ok()),
            Some("keep-alive, Upgrade")
        );
        assert_eq!(
            request
                .headers
                .get("upgrade")
                .and_then(|value| value.to_str().ok()),
            Some("websocket")
        );
        assert_eq!(
            request
                .headers
                .get("x-forwarded-proto")
                .and_then(|value| value.to_str().ok()),
            Some("https")
        );
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn appends_forwarded_for_when_configured() {
        let policy = crate::config::RequestHeaderPolicyConfig {
            strip_inbound_client_ip_headers: false,
            x_forwarded_for: crate::config::ForwardedClientIpHeaderMode::Append,
            ..crate::config::RequestHeaderPolicyConfig::default()
        };
        let mut request = RequestHeader::build("GET", b"/", Some(4)).unwrap();
        request
            .insert_header("x-forwarded-for", "198.51.100.9")
            .unwrap();
        let client_addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 53210));

        apply_upstream_request_policy(
            &mut request,
            &policy,
            test_upstream_context(&client_addr, true, None, false, None, None),
        )
        .unwrap();

        assert_eq!(
            request
                .headers
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok()),
            Some("198.51.100.9, 203.0.113.10")
        );
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn trusted_proxy_recursively_restores_forwarded_client_ip() {
        let policy = crate::config::RequestHeaderPolicyConfig {
            strip_inbound_client_ip_headers: false,
            x_real_ip: true,
            forwarded: true,
            set: std::collections::BTreeMap::from([(
                "x-template-remote".to_owned(),
                "{remote_addr}".to_owned(),
            )]),
            ..crate::config::RequestHeaderPolicyConfig::default()
        };
        let mut request = RequestHeader::build("GET", b"/", Some(4)).unwrap();
        request.insert_header("host", "example.test").unwrap();
        request
            .insert_header("x-forwarded-for", "198.51.100.9, 203.0.113.10")
            .unwrap();
        let client_addr = SocketAddr::from((Ipv4Addr::new(10, 89, 0, 254), 53210));
        let matcher = |address: IpAddr| match address {
            IpAddr::V4(address) => {
                address == Ipv4Addr::new(10, 89, 0, 254)
                    || address == Ipv4Addr::new(203, 0, 113, 10)
            }
            IpAddr::V6(_) => false,
        };

        apply_upstream_request_policy(
            &mut request,
            &policy,
            test_upstream_context(&client_addr, true, Some(&matcher), true, None, None),
        )
        .unwrap();

        assert_eq!(
            request
                .headers
                .get("x-real-ip")
                .and_then(|value| value.to_str().ok()),
            Some("198.51.100.9")
        );
        assert_eq!(
            request
                .headers
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok()),
            Some("198.51.100.9")
        );
        assert_eq!(
            request
                .headers
                .get("forwarded")
                .and_then(|value| value.to_str().ok()),
            Some("for=198.51.100.9;host=\"example.test\";proto=https")
        );
        assert_eq!(
            request
                .headers
                .get("x-template-remote")
                .and_then(|value| value.to_str().ok()),
            Some("198.51.100.9")
        );
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn untrusted_append_mode_ignores_inbound_forwarded_for() {
        let policy = crate::config::RequestHeaderPolicyConfig {
            strip_inbound_client_ip_headers: false,
            x_forwarded_for: crate::config::ForwardedClientIpHeaderMode::Append,
            ..crate::config::RequestHeaderPolicyConfig::default()
        };
        let mut request = RequestHeader::build("GET", b"/", Some(4)).unwrap();
        request
            .insert_header("x-forwarded-for", "198.51.100.9")
            .unwrap();
        let client_addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 53210));

        apply_upstream_request_policy(
            &mut request,
            &policy,
            test_upstream_context(&client_addr, false, None, false, None, None),
        )
        .unwrap();

        assert_eq!(
            request
                .headers
                .get("x-forwarded-for")
                .and_then(|value| value.to_str().ok()),
            Some("203.0.113.10")
        );
    }

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn emits_standard_forwarded_header_when_enabled() {
        let policy = crate::config::RequestHeaderPolicyConfig {
            forwarded: true,
            ..crate::config::RequestHeaderPolicyConfig::default()
        };
        let mut request = RequestHeader::build("GET", b"/", Some(4)).unwrap();
        request.insert_header("host", "example.test").unwrap();
        let client_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53210);

        apply_upstream_request_policy(
            &mut request,
            &policy,
            test_upstream_context(&client_addr, false, None, true, None, None),
        )
        .unwrap();

        assert_eq!(
            request
                .headers
                .get("forwarded")
                .and_then(|value| value.to_str().ok()),
            Some("for=\"[::1]\";host=\"example.test\";proto=https")
        );
    }

    #[cfg(feature = "privacy-mode")]
    #[test]
    fn privacy_mode_strips_client_ip_headers_without_synthesizing_new_ones() {
        let policy = crate::config::RequestHeaderPolicyConfig {
            x_forwarded_for: crate::config::ForwardedClientIpHeaderMode::Replace,
            forwarded: true,
            set: std::collections::BTreeMap::from([(
                "x-proxy-by".to_owned(),
                "configured-value".to_owned(),
            )]),
            ..crate::config::RequestHeaderPolicyConfig::default()
        };
        let mut request = RequestHeader::build("GET", b"/", Some(8)).unwrap();
        request.insert_header("host", "example.test").unwrap();
        request
            .insert_header("x-forwarded-for", "198.51.100.9")
            .unwrap();
        request.insert_header("x-real-ip", "198.51.100.9").unwrap();
        request
            .insert_header("forwarded", "for=198.51.100.9")
            .unwrap();
        let client_addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 53210));

        apply_upstream_request_policy(
            &mut request,
            &policy,
            UpstreamRequestPolicyContext {
                client_addr: Some(&client_addr),
                trusted_proxy: false,
                trusted_proxy_matcher: None,
                downstream_tls: true,
                request_id: None,
                tls_identity: None,
                route_regex_captures: None,
            },
        )
        .unwrap();

        assert!(request.headers.get("x-forwarded-for").is_none());
        assert!(request.headers.get("x-real-ip").is_none());
        assert!(request.headers.get("forwarded").is_none());
        assert_eq!(
            request
                .headers
                .get("x-proxy-by")
                .and_then(|value| value.to_str().ok()),
            Some("configured-value")
        );
    }
}
