use std::net::Ipv6Addr;

use fluxheim_common::path_safety::safe_forward_path;
use fluxheim_config::{HttpsRedirectConfig, normalize_host};
use fluxheim_protocol::{Http1RequestTarget, http1_request_target};

use crate::native_http1_route_response_headers::NativeRouteResponseHeaderPolicy;
use crate::{NativeHttp1Request, NativeHttp1Response};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativeHttp1RouteRedirect {
    pub(crate) to: String,
    pub(crate) status: u16,
}

pub(crate) fn redirect_response(
    request: &NativeHttp1Request,
    redirect: &NativeHttp1RouteRedirect,
) -> NativeHttp1Response {
    let Some(location) = route_redirect_location(request, redirect) else {
        return NativeHttp1Response::new(400, "Bad Request", b"invalid redirect target\n")
            .close_connection();
    };
    NativeHttp1Response::new(
        redirect.status,
        redirect_reason(redirect.status),
        Vec::new(),
    )
    .with_header("location", location)
}

pub(crate) fn https_redirect_response(
    request: &NativeHttp1Request,
    config: &HttpsRedirectConfig,
    response_headers: &NativeRouteResponseHeaderPolicy,
) -> Option<NativeHttp1Response> {
    if !config.enabled || request.downstream_tls {
        return None;
    }
    let Some(location) = https_redirect_location(request, config) else {
        return Some(
            NativeHttp1Response::new(400, "Bad Request", b"missing or invalid host\n")
                .close_connection(),
        );
    };
    let mut response =
        NativeHttp1Response::new(config.status, redirect_reason(config.status), Vec::new())
            .with_header("location", location)
            .with_header("content-length", "0");
    response_headers.apply_for_request(request, &mut response);
    response_headers.apply_digests_for_method(&request.method, &mut response);
    Some(response)
}

pub(crate) fn redirect_reason(status: u16) -> &'static str {
    match status {
        301 => "Moved Permanently",
        302 => "Found",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        _ => "Redirect",
    }
}

pub(crate) fn https_redirect_location(
    request: &NativeHttp1Request,
    config: &HttpsRedirectConfig,
) -> Option<String> {
    let host = request_header_value(request, "host")?;
    let normalized_host = normalize_host(host)?;
    let authority = redirect_authority(&normalized_host, config.target_port)?;
    let target = request.target.as_str();
    if !target.starts_with('/') || target.chars().any(char::is_control) {
        return None;
    }
    Some(format!("https://{authority}{target}"))
}

fn redirect_authority(host: &str, target_port: Option<u16>) -> Option<String> {
    let host = if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]")
    } else {
        host.to_owned()
    };

    match target_port {
        Some(443) | None => Some(host),
        Some(0) => None,
        Some(port) => Some(format!("{host}:{port}")),
    }
}

fn route_redirect_location(
    request: &NativeHttp1Request,
    redirect: &NativeHttp1RouteRedirect,
) -> Option<String> {
    let (path, query) = request_path_and_query(request)?;
    let uri = query
        .as_deref()
        .map(|query| format!("{path}?{query}"))
        .unwrap_or_else(|| path.clone());
    if !safe_forward_path(&path) || uri.chars().any(char::is_control) {
        return None;
    }
    if redirect_template_substitutes_query_into_path(&redirect.to)
        && !redirect_query_path_expansion_safe(query.as_deref().unwrap_or_default())
    {
        return None;
    }

    let location = redirect
        .to
        .replace("{uri}", &uri)
        .replace("{path}", &path)
        .replace("{query}", query.as_deref().unwrap_or_default());
    valid_redirect_location(&location).then_some(location)
}

fn redirect_template_substitutes_query_into_path(template: &str) -> bool {
    let Some(query_token) = template.find("{query}") else {
        return false;
    };
    let query_tail = template.find(['?', '#']).unwrap_or(template.len());
    query_token < query_tail
}

fn redirect_query_path_expansion_safe(query: &str) -> bool {
    if query.is_empty() || query.chars().any(char::is_control) {
        return query.is_empty();
    }
    safe_forward_path(&format!("/{query}"))
}

fn valid_redirect_location(location: &str) -> bool {
    if !(location.starts_with("https://") || location.starts_with("http://"))
        || !redirect_location_path_safe(location)
    {
        return false;
    }
    !location.contains('{')
        && !location.contains('}')
        && !location.contains('\\')
        && !location
            .chars()
            .any(|character| character.is_control() || character.is_whitespace())
}

fn redirect_location_path_safe(location: &str) -> bool {
    let Some(rest) = location
        .strip_prefix("https://")
        .or_else(|| location.strip_prefix("http://"))
    else {
        return false;
    };
    let path_and_tail = rest
        .find('/')
        .map(|path_start| &rest[path_start..])
        .unwrap_or_default();
    let path_end = path_and_tail
        .find(['?', '#'])
        .unwrap_or(path_and_tail.len());
    let path = &path_and_tail[..path_end];
    path.is_empty() || safe_forward_path(path)
}

fn request_path_and_query(request: &NativeHttp1Request) -> Option<(String, Option<String>)> {
    match http1_request_target(&request.method, &request.target).ok()? {
        Http1RequestTarget::Origin { path, query, .. } => {
            Some((path.to_owned(), query.map(str::to_owned)))
        }
        Http1RequestTarget::AbsoluteUri { path, query, .. } => {
            Some((path.unwrap_or("/").to_owned(), query.map(str::to_owned)))
        }
        Http1RequestTarget::Authority { .. } | Http1RequestTarget::Asterisk => None,
    }
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
