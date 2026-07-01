use fluxheim_common::path_safety::safe_forward_path;
use fluxheim_protocol::{Http1RequestTarget, http1_request_target, route_strip_prefix_suffix};

use crate::NativeHttp1Request;
use crate::native_http1_route_matcher::NativeHttp1RouteMatcher;

pub(crate) struct NativeRouteRewritePolicy<'a> {
    matcher: &'a NativeHttp1RouteMatcher,
    strip_prefix: Option<&'a str>,
    rewrite_prefix: Option<&'a str>,
    rewrite_template: Option<&'a str>,
}

impl<'a> NativeRouteRewritePolicy<'a> {
    pub(crate) const fn new(
        matcher: &'a NativeHttp1RouteMatcher,
        strip_prefix: Option<&'a str>,
        rewrite_prefix: Option<&'a str>,
        rewrite_template: Option<&'a str>,
    ) -> Self {
        Self {
            matcher,
            strip_prefix,
            rewrite_prefix,
            rewrite_template,
        }
    }
}

pub(crate) fn request_path_and_query(
    request: &NativeHttp1Request,
) -> Option<(String, Option<String>)> {
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

pub(crate) fn rewrite_route_request(
    mut request: NativeHttp1Request,
    policy: NativeRouteRewritePolicy<'_>,
    path: &str,
    query: Option<&str>,
) -> Option<NativeHttp1Request> {
    if let Some(template) = policy.rewrite_template {
        let rewritten_path = route_rewrite_template_path(path, policy.matcher, template)?;
        if !safe_forward_path(&rewritten_path) {
            return None;
        }
        request.target = query
            .map(|query| format!("{rewritten_path}?{query}"))
            .unwrap_or(rewritten_path);
        return Some(request);
    }

    let Some(strip_prefix) = policy.strip_prefix else {
        return Some(request);
    };
    let suffix = route_strip_prefix_suffix(strip_prefix, path)?;
    let rewritten_path = if let Some(rewrite_prefix) = policy.rewrite_prefix {
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
    request.target = query
        .map(|query| format!("{rewritten_path}?{query}"))
        .unwrap_or(rewritten_path);
    Some(request)
}

fn route_rewrite_template_path(
    path: &str,
    matcher: &NativeHttp1RouteMatcher,
    template: &str,
) -> Option<String> {
    let mut rewritten = String::with_capacity(template.len());
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        rewritten.push_str(&rest[..open]);
        let after_open = &rest[open + 1..];
        let close = after_open.find('}')?;
        let variable = &after_open[..close];
        if let Some(value) = matcher.capture_value(path, variable) {
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

fn append_route_regex_capture_value(rewritten: &mut String, value: &str) {
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
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
