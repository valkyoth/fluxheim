use std::net::{IpAddr, SocketAddr};

#[cfg(not(feature = "privacy-mode"))]
use crate::config::{
    ForwardedClientIpHeaderMode, HeaderValues, RequestHeaderPolicyConfig,
    ResponseHeaderPolicyConfig,
};
#[cfg(feature = "privacy-mode")]
use crate::config::{HeaderValues, RequestHeaderPolicyConfig, ResponseHeaderPolicyConfig};

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
    request: &mut pingora::http::RequestHeader,
    policy: &RequestHeaderPolicyConfig,
    client_addr: Option<&SocketAddr>,
    trusted_proxy: bool,
    downstream_tls: bool,
    request_id: Option<&str>,
) -> pingora::Result<()> {
    #[cfg(feature = "privacy-mode")]
    {
        let _ = (client_addr, trusted_proxy, downstream_tls, request_id);
        return apply_privacy_upstream_request_policy(request, policy, request_id);
    }

    #[cfg(not(feature = "privacy-mode"))]
    {
        apply_standard_upstream_request_policy(
            request,
            policy,
            client_addr,
            trusted_proxy,
            downstream_tls,
            request_id,
        )
    }
}

#[cfg(feature = "privacy-mode")]
fn apply_privacy_upstream_request_policy(
    request: &mut pingora::http::RequestHeader,
    policy: &RequestHeaderPolicyConfig,
    request_id: Option<&str>,
) -> pingora::Result<()> {
    if policy.enabled {
        let unset = policy.effective_unset();
        let set = policy.effective_set();
        let context = RequestHeaderTemplateContext::new(request, None, false, request_id);
        apply_request_mutations(request, &unset, &set, &policy.append, &context)?;
    }
    for header in SPOOFABLE_CLIENT_IP_HEADERS {
        request.remove_header(*header);
    }
    Ok(())
}

#[cfg(not(feature = "privacy-mode"))]
fn apply_standard_upstream_request_policy(
    request: &mut pingora::http::RequestHeader,
    policy: &RequestHeaderPolicyConfig,
    client_addr: Option<&SocketAddr>,
    trusted_proxy: bool,
    downstream_tls: bool,
    request_id: Option<&str>,
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
    let proto = if downstream_tls { "https" } else { "http" };

    if policy.strip_inbound_client_ip_headers {
        for header in SPOOFABLE_CLIENT_IP_HEADERS {
            request.remove_header(*header);
        }
    }

    if policy.x_real_ip {
        if let Some(client_addr) = client_addr {
            request.insert_header("x-real-ip", client_addr.ip().to_string())?;
        } else {
            request.remove_header("x-real-ip");
        }
    }

    if let Some(client_addr) = client_addr {
        apply_x_forwarded_for(
            request,
            policy.x_forwarded_for,
            trusted_proxy
                .then_some(original_x_forwarded_for.as_deref())
                .flatten(),
            client_addr.ip(),
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
        && let Some(client_addr) = client_addr
    {
        request.insert_header(
            "forwarded",
            build_forwarded_header(client_addr.ip(), original_host.as_deref(), proto),
        )?;
    }

    let unset = policy.effective_unset();
    let set = policy.effective_set();
    let context = RequestHeaderTemplateContext::new(
        request,
        client_addr.map(SocketAddr::ip),
        downstream_tls,
        request_id,
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
}

impl RequestHeaderTemplateContext {
    fn new(
        request: &pingora::http::RequestHeader,
        client_ip: Option<IpAddr>,
        downstream_tls: bool,
        request_id: Option<&str>,
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
            variable => variable
                .strip_prefix("http.")
                .and_then(|name| self.headers.get(name))
                .and_then(|value| value.to_str().ok()),
        }
    }
}

pub fn apply_response_policy(
    response: &mut pingora::http::ResponseHeader,
    policy: &ResponseHeaderPolicyConfig,
) -> pingora::Result<()> {
    if !policy.enabled {
        return Ok(());
    }

    set_optional_header(
        response,
        "strict-transport-security",
        policy.strict_transport_security.as_deref(),
    )?;
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
    Ok(())
}

fn apply_request_mutations(
    request: &mut pingora::http::RequestHeader,
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
            rendered.push_str(value);
        }
        rest = &after_open[close + 1..];
    }

    rendered.push_str(rest);
    rendered
}

fn apply_response_mutations(
    response: &mut pingora::http::ResponseHeader,
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

#[cfg(not(feature = "privacy-mode"))]
fn apply_x_forwarded_for(
    request: &mut pingora::http::RequestHeader,
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
    response: &mut pingora::http::ResponseHeader,
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

    use super::{apply_response_policy, apply_upstream_request_policy};

    #[test]
    fn applies_default_response_headers() {
        let policy = crate::config::ResponseHeaderPolicyConfig::default();
        let mut response = pingora::http::ResponseHeader::build(200, None).unwrap();
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
        let mut response = pingora::http::ResponseHeader::build(200, None).unwrap();

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
        let mut response = pingora::http::ResponseHeader::build(200, None).unwrap();
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
        let mut response = pingora::http::ResponseHeader::build(200, None).unwrap();
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
        let mut response = pingora::http::ResponseHeader::build(200, None).unwrap();
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

    #[cfg(not(feature = "privacy-mode"))]
    #[test]
    fn applies_default_upstream_request_headers() {
        let policy = crate::config::RequestHeaderPolicyConfig::default();
        let mut request = pingora::http::RequestHeader::build("GET", b"/", Some(8)).unwrap();
        request.insert_header("host", "example.test").unwrap();
        request
            .insert_header("x-forwarded-for", "198.51.100.9")
            .unwrap();
        request.insert_header("x-real-ip", "198.51.100.9").unwrap();
        let client_addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 53210));

        apply_upstream_request_policy(&mut request, &policy, Some(&client_addr), false, true, None)
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
        let mut request = pingora::http::RequestHeader::build("GET", b"/", Some(8)).unwrap();
        request.insert_header("host", "example.test").unwrap();
        let client_addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 53210));

        apply_upstream_request_policy(&mut request, &policy, Some(&client_addr), false, true, None)
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
        let mut request = pingora::http::RequestHeader::build("GET", b"/", Some(8)).unwrap();
        request.insert_header("host", "example.test").unwrap();
        request
            .insert_header("x-powered-by", "origin-version")
            .unwrap();
        let client_addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 53210));

        apply_upstream_request_policy(&mut request, &policy, Some(&client_addr), false, true, None)
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
                ("upgrade".to_owned(), "{http.upgrade}".to_owned()),
            ]),
            ..crate::config::RequestHeaderPolicyConfig::default()
        };
        let mut request =
            pingora::http::RequestHeader::build("GET", b"/chat/?room=main", Some(8)).unwrap();
        request.insert_header("host", "example.test").unwrap();
        request.insert_header("upgrade", "websocket").unwrap();
        let client_addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 53210));

        apply_upstream_request_policy(
            &mut request,
            &policy,
            Some(&client_addr),
            false,
            true,
            Some("req-123"),
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
                .get("upgrade")
                .and_then(|value| value.to_str().ok()),
            Some("websocket")
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
        let mut request = pingora::http::RequestHeader::build("GET", b"/", Some(8)).unwrap();
        request.insert_header("host", "example.test").unwrap();
        request
            .insert_header("x-powered-by", "origin-version")
            .unwrap();
        request.insert_header("x-debug", "1").unwrap();
        let client_addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 53210));

        apply_upstream_request_policy(&mut request, &policy, Some(&client_addr), false, true, None)
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
        let mut request =
            pingora::http::RequestHeader::build("GET", b"/chat/room", Some(8)).unwrap();
        request.insert_header("host", "example.test").unwrap();
        request
            .insert_header("connection", "keep-alive, Upgrade")
            .unwrap();
        request.insert_header("upgrade", "websocket").unwrap();
        let client_addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 53210));

        apply_upstream_request_policy(&mut request, &policy, Some(&client_addr), false, true, None)
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
        let mut request = pingora::http::RequestHeader::build("GET", b"/", Some(4)).unwrap();
        request
            .insert_header("x-forwarded-for", "198.51.100.9")
            .unwrap();
        let client_addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 53210));

        apply_upstream_request_policy(&mut request, &policy, Some(&client_addr), true, false, None)
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
    fn untrusted_append_mode_ignores_inbound_forwarded_for() {
        let policy = crate::config::RequestHeaderPolicyConfig {
            strip_inbound_client_ip_headers: false,
            x_forwarded_for: crate::config::ForwardedClientIpHeaderMode::Append,
            ..crate::config::RequestHeaderPolicyConfig::default()
        };
        let mut request = pingora::http::RequestHeader::build("GET", b"/", Some(4)).unwrap();
        request
            .insert_header("x-forwarded-for", "198.51.100.9")
            .unwrap();
        let client_addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 53210));

        apply_upstream_request_policy(
            &mut request,
            &policy,
            Some(&client_addr),
            false,
            false,
            None,
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
        let mut request = pingora::http::RequestHeader::build("GET", b"/", Some(4)).unwrap();
        request.insert_header("host", "example.test").unwrap();
        let client_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 53210);

        apply_upstream_request_policy(&mut request, &policy, Some(&client_addr), false, true, None)
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
        let mut request = pingora::http::RequestHeader::build("GET", b"/", Some(8)).unwrap();
        request.insert_header("host", "example.test").unwrap();
        request
            .insert_header("x-forwarded-for", "198.51.100.9")
            .unwrap();
        request.insert_header("x-real-ip", "198.51.100.9").unwrap();
        request
            .insert_header("forwarded", "for=198.51.100.9")
            .unwrap();
        let client_addr = SocketAddr::from((Ipv4Addr::new(203, 0, 113, 10), 53210));

        apply_upstream_request_policy(&mut request, &policy, Some(&client_addr), false, true, None)
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
