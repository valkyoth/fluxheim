#[cfg(not(feature = "privacy-mode"))]
use fluxheim_config::ForwardedClientIpHeaderMode;
use fluxheim_config::{HeaderValues, RequestHeaderPolicyConfig};
use fluxheim_headers::SPOOFABLE_CLIENT_IP_HEADERS;
#[cfg(not(feature = "privacy-mode"))]
use fluxheim_headers::{ForwardedProto, build_forwarded_header, effective_client_ip};

use crate::NativeHttp1Request;
#[cfg(not(feature = "privacy-mode"))]
use crate::ProxyProtocolTrustedSource;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct NativeRouteRequestHeaderPolicy {
    enabled: bool,
    strip_inbound_client_ip_headers: bool,
    #[cfg(not(feature = "privacy-mode"))]
    x_forwarded_for: ForwardedClientIpHeaderMode,
    #[cfg(not(feature = "privacy-mode"))]
    x_real_ip: bool,
    #[cfg(not(feature = "privacy-mode"))]
    x_forwarded_host: bool,
    #[cfg(not(feature = "privacy-mode"))]
    x_forwarded_proto: bool,
    #[cfg(not(feature = "privacy-mode"))]
    forwarded: bool,
    #[cfg(not(feature = "privacy-mode"))]
    trusted_sources: Vec<ProxyProtocolTrustedSource>,
    unset: Vec<String>,
    set: Vec<(String, String)>,
    append: Vec<(String, String)>,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct NativeRequestHeaderTemplateContext {
    route_regex_captures: Vec<(String, String)>,
}

impl NativeRouteRequestHeaderPolicy {
    pub(crate) fn from_policy(policy: &RequestHeaderPolicyConfig) -> Self {
        Self {
            enabled: policy.enabled,
            strip_inbound_client_ip_headers: policy.strip_inbound_client_ip_headers,
            #[cfg(not(feature = "privacy-mode"))]
            x_forwarded_for: policy.x_forwarded_for,
            #[cfg(not(feature = "privacy-mode"))]
            x_real_ip: policy.x_real_ip,
            #[cfg(not(feature = "privacy-mode"))]
            x_forwarded_host: policy.x_forwarded_host,
            #[cfg(not(feature = "privacy-mode"))]
            x_forwarded_proto: policy.x_forwarded_proto,
            #[cfg(not(feature = "privacy-mode"))]
            forwarded: policy.forwarded,
            #[cfg(not(feature = "privacy-mode"))]
            trusted_sources: Vec::new(),
            unset: policy.effective_unset(),
            set: policy.effective_set().into_iter().collect(),
            append: flatten_append_headers(&policy.append),
        }
    }

    pub(crate) fn from_overlay(
        overlay: &fluxheim_config::RequestHeaderPolicyOverlayConfig,
    ) -> Self {
        let mut policy = Self::from_policy(&RequestHeaderPolicyConfig::default());
        if let Some(enabled) = overlay.enabled {
            policy.enabled = enabled;
        }
        if let Some(strip) = overlay.strip_inbound_client_ip_headers {
            policy.strip_inbound_client_ip_headers = strip;
        }
        #[cfg(not(feature = "privacy-mode"))]
        {
            if let Some(mode) = overlay.x_forwarded_for {
                policy.x_forwarded_for = mode;
            }
            if let Some(x_real_ip) = overlay.x_real_ip {
                policy.x_real_ip = x_real_ip;
            }
            if let Some(x_forwarded_host) = overlay.x_forwarded_host {
                policy.x_forwarded_host = x_forwarded_host;
            }
            if let Some(x_forwarded_proto) = overlay.x_forwarded_proto {
                policy.x_forwarded_proto = x_forwarded_proto;
            }
            if let Some(forwarded) = overlay.forwarded {
                policy.forwarded = forwarded;
            }
        }
        policy.unset = overlay.effective_unset();
        policy.set = overlay.effective_set().into_iter().collect();
        policy.append = flatten_append_headers(&overlay.append);
        policy
    }

    pub(crate) fn apply(
        &self,
        request: &mut NativeHttp1Request,
        context: Option<&NativeRequestHeaderTemplateContext>,
    ) {
        if !self.enabled {
            #[cfg(feature = "privacy-mode")]
            strip_spoofable_client_ip_headers(request);
            return;
        }
        #[cfg(not(feature = "privacy-mode"))]
        self.apply_forwarded_headers(request);
        for name in &self.unset {
            request
                .headers
                .retain(|(header_name, _)| !header_name.eq_ignore_ascii_case(name));
        }
        for (name, value) in &self.set {
            request
                .headers
                .retain(|(header_name, _)| !header_name.eq_ignore_ascii_case(name));
            let value = render_native_request_header_template(value, request, context);
            if !value.is_empty() {
                request.headers.push((name.clone(), value));
            }
        }
        for (name, value) in &self.append {
            let value = render_native_request_header_template(value, request, context);
            if !value.is_empty() {
                request.headers.push((name.clone(), value));
            }
        }
        #[cfg(feature = "privacy-mode")]
        strip_spoofable_client_ip_headers(request);
    }

    #[cfg(not(feature = "privacy-mode"))]
    fn apply_forwarded_headers(&self, request: &mut NativeHttp1Request) {
        let original_host = header_value(request, "host").map(str::to_owned);
        let (proto, forwarded_proto) = if request.downstream_tls {
            ("https", ForwardedProto::Https)
        } else {
            ("http", ForwardedProto::Http)
        };

        if self.strip_inbound_client_ip_headers {
            strip_spoofable_client_ip_headers(request);
        }

        let original_x_forwarded_for = joined_header_value(request, "x-forwarded-for");
        let listener_effective_addr = request.effective_client_addr;
        let direct_ip = request.peer_addr.map(|addr| addr.ip());
        let trusted_direct_peer = direct_ip.is_some_and(|ip| self.trusted_source_contains(ip));
        let trusted_proxy_matcher = |ip| self.trusted_source_contains(ip);
        let client_ip = listener_effective_addr.map(|addr| addr.ip()).or_else(|| {
            direct_ip.map(|ip| {
                effective_client_ip(
                    ip,
                    trusted_direct_peer,
                    original_x_forwarded_for.as_deref(),
                    Some(&trusted_proxy_matcher),
                )
            })
        });
        if let Some(client_ip) = client_ip {
            let port = listener_effective_addr
                .filter(|addr| addr.ip() == client_ip)
                .map(|addr| addr.port())
                .or_else(|| {
                    request
                        .peer_addr
                        .filter(|addr| addr.ip() == client_ip)
                        .map(|addr| addr.port())
                })
                .unwrap_or(0);
            request.effective_client_addr = Some(std::net::SocketAddr::new(client_ip, port));
        }
        match (self.x_forwarded_for, client_ip) {
            (ForwardedClientIpHeaderMode::Off, _) => {
                remove_request_header(request, "x-forwarded-for")
            }
            (ForwardedClientIpHeaderMode::Replace, Some(ip)) => {
                replace_request_header(request, "x-forwarded-for", ip.to_string());
            }
            (ForwardedClientIpHeaderMode::Append, Some(ip)) => {
                let value = trusted_direct_peer
                    .then_some(original_x_forwarded_for.as_deref())
                    .flatten()
                    .filter(|value| !value.trim().is_empty())
                    .map(|value| format!("{value}, {ip}"))
                    .unwrap_or_else(|| ip.to_string());
                replace_request_header(request, "x-forwarded-for", value);
            }
            (ForwardedClientIpHeaderMode::Replace | ForwardedClientIpHeaderMode::Append, None) => {
                remove_request_header(request, "x-forwarded-for");
            }
        }

        if self.x_real_ip {
            if let Some(ip) = client_ip {
                replace_request_header(request, "x-real-ip", ip.to_string());
            } else {
                remove_request_header(request, "x-real-ip");
            }
        }

        if self.x_forwarded_host {
            if let Some(host) = &original_host {
                replace_request_header(request, "x-forwarded-host", host.clone());
            } else {
                remove_request_header(request, "x-forwarded-host");
            }
        }

        if self.x_forwarded_proto {
            replace_request_header(request, "x-forwarded-proto", proto);
        }

        if self.forwarded {
            if let Some(ip) = client_ip {
                if let Some(value) =
                    build_forwarded_header(ip, original_host.as_deref(), forwarded_proto)
                {
                    replace_request_header(request, "forwarded", value);
                } else {
                    remove_request_header(request, "forwarded");
                }
            } else {
                remove_request_header(request, "forwarded");
            }
        }
    }

    #[cfg(not(feature = "privacy-mode"))]
    pub(crate) fn set_trusted_sources(&mut self, trusted_sources: Vec<ProxyProtocolTrustedSource>) {
        self.trusted_sources = trusted_sources;
    }

    #[cfg(not(feature = "privacy-mode"))]
    fn trusted_source_contains(&self, address: std::net::IpAddr) -> bool {
        self.trusted_sources
            .iter()
            .any(|source| source.contains(address))
    }
}

impl NativeRequestHeaderTemplateContext {
    pub(crate) fn from_captures(route_regex_captures: Vec<(String, String)>) -> Self {
        Self {
            route_regex_captures,
        }
    }

    fn variable(&self, variable: &str) -> Option<&str> {
        self.route_regex_captures
            .iter()
            .find_map(|(name, value)| (name == variable).then_some(value.as_str()))
    }
}

pub(crate) fn default_native_request_header_policy() -> NativeRouteRequestHeaderPolicy {
    NativeRouteRequestHeaderPolicy::from_policy(&RequestHeaderPolicyConfig::default())
}

fn request_header_value<'a>(request: &'a NativeHttp1Request, name: &str) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find(|(header_name, value)| {
            header_name.eq_ignore_ascii_case(name) && !value.trim().is_empty()
        })
        .map(|(_, value)| value.trim())
}

#[cfg(not(feature = "privacy-mode"))]
fn header_value<'a>(request: &'a NativeHttp1Request, name: &str) -> Option<&'a str> {
    request_header_value(request, name)
}

#[cfg(not(feature = "privacy-mode"))]
pub(crate) fn joined_header_value(request: &NativeHttp1Request, name: &str) -> Option<String> {
    let mut values = request
        .headers
        .iter()
        .filter(|(header_name, value)| {
            header_name.eq_ignore_ascii_case(name) && !value.trim().is_empty()
        })
        .map(|(_, value)| value.trim());
    let first = values.next()?.to_owned();
    Some(values.fold(first, |mut joined, value| {
        joined.push_str(", ");
        joined.push_str(value);
        joined
    }))
}

fn strip_spoofable_client_ip_headers(request: &mut NativeHttp1Request) {
    request.headers.retain(|(header_name, _)| {
        !SPOOFABLE_CLIENT_IP_HEADERS
            .iter()
            .any(|blocked| header_name.eq_ignore_ascii_case(blocked))
    });
}

#[cfg(not(feature = "privacy-mode"))]
fn remove_request_header(request: &mut NativeHttp1Request, name: &str) {
    request
        .headers
        .retain(|(header_name, _)| !header_name.eq_ignore_ascii_case(name));
}

#[cfg(not(feature = "privacy-mode"))]
fn replace_request_header(
    request: &mut NativeHttp1Request,
    name: impl Into<String>,
    value: impl Into<String>,
) {
    let name = name.into();
    remove_request_header(request, &name);
    request.headers.push((name, value.into()));
}

fn render_native_request_header_template(
    value: &str,
    request: &NativeHttp1Request,
    context: Option<&NativeRequestHeaderTemplateContext>,
) -> String {
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
        if let Some(value) = native_request_header_template_variable(variable, request, context) {
            rendered.extend(value.chars().filter(|character| !character.is_control()));
        }
        rest = &after_open[close + 1..];
    }

    rendered.push_str(rest);
    rendered
}

fn native_request_header_template_variable(
    variable: &str,
    request: &NativeHttp1Request,
    context: Option<&NativeRequestHeaderTemplateContext>,
) -> Option<String> {
    if let Some(value) = context.and_then(|context| context.variable(variable)) {
        return Some(value.to_owned());
    }
    match variable {
        "host" => request_header_value(request, "host").map(str::to_owned),
        "scheme" => Some(
            if request.downstream_tls {
                "https"
            } else {
                "http"
            }
            .to_owned(),
        ),
        "uri" => Some(request.target.clone()),
        "path" => Some(
            request
                .target
                .split_once('?')
                .map(|(path, _)| path)
                .unwrap_or(request.target.as_str())
                .to_owned(),
        ),
        "query" => request
            .target
            .split_once('?')
            .map(|(_, query)| query.to_owned()),
        "request_id" => request_header_value(request, "x-request-id").map(str::to_owned),
        "tls.client_cert_sha256" => request
            .tls_identity
            .as_ref()
            .and_then(|identity| identity.cert_sha256.clone()),
        "tls.client_cert_serial" => request
            .tls_identity
            .as_ref()
            .and_then(|identity| identity.serial_number.clone()),
        "tls.version" => request
            .tls_identity
            .as_ref()
            .and_then(|identity| identity.version.clone()),
        "http.upgrade" => request_header_value(request, "upgrade").map(str::to_owned),
        #[cfg(not(feature = "privacy-mode"))]
        "remote_addr" => request
            .effective_client_addr
            .as_ref()
            .or(request.peer_addr.as_ref())
            .map(std::net::SocketAddr::ip)
            .map(|ip| ip.to_string()),
        #[cfg(feature = "privacy-mode")]
        "remote_addr" => None,
        _ => None,
    }
}

fn flatten_append_headers(
    append: &std::collections::BTreeMap<String, HeaderValues>,
) -> Vec<(String, String)> {
    let mut flattened = Vec::new();
    for (name, values) in append {
        for value in values.iter() {
            flattened.push((name.clone(), value.to_owned()));
        }
    }
    flattened
}
