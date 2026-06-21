use std::future::Future;
use std::pin::Pin;

use fluxheim_common::path_safety::safe_forward_path;
use fluxheim_config::{HeaderValues, ResponseHeaderPolicyOverlayConfig};
use fluxheim_protocol::{
    Http1RequestTarget, http1_request_target, route_method_matches, route_prefix_matches_path,
    route_strip_prefix_suffix,
};

use crate::{
    NativeHttp1Handler, NativeHttp1Proxy, NativeHttp1Request, NativeHttp1Response,
    NativeHttp1StaticWeb,
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHttp1RouteProxy {
    routes: Vec<NativeHttp1RouteProxyRoute>,
    fallback: Option<NativeHttp1Proxy>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NativeHttp1RouteProxyRoute {
    methods: Vec<String>,
    matcher: NativeHttp1RouteMatcher,
    strip_prefix: Option<String>,
    rewrite_prefix: Option<String>,
    max_request_body_bytes: Option<u64>,
    response_headers: NativeRouteResponseHeaderPolicy,
    action: NativeHttp1RouteAction,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum NativeHttp1RouteMatcher {
    Exact(String),
    Prefix(String),
    Fallback,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum NativeHttp1RouteAction {
    Proxy(NativeHttp1Proxy),
    Redirect(NativeHttp1RouteRedirect),
    StaticWeb(NativeHttp1StaticWeb),
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct NativeHttp1RouteRedirect {
    to: String,
    status: u16,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct NativeRouteResponseHeaderPolicy {
    enabled: bool,
    unset: Vec<String>,
    set: Vec<(String, String)>,
    append: Vec<(String, String)>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeHttp1RouteProxyConfigError {
    MissingRouteAction,
    RegexRoute,
    RewriteTemplate,
    StaticWeb,
}

impl std::fmt::Display for NativeHttp1RouteProxyConfigError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingRouteAction => {
                formatter.write_str("native route proxy requires an action")
            }
            Self::RegexRoute => {
                formatter.write_str("native route proxy does not yet support regex routes")
            }
            Self::RewriteTemplate => {
                formatter.write_str("native route proxy does not yet support rewrite_template")
            }
            Self::StaticWeb => formatter.write_str("native route static web config is invalid"),
        }
    }
}

impl std::error::Error for NativeHttp1RouteProxyConfigError {}

impl NativeHttp1RouteProxy {
    pub fn new(
        routes: Vec<NativeHttp1RouteProxyRoute>,
        fallback: Option<NativeHttp1Proxy>,
    ) -> Self {
        Self { routes, fallback }
    }

    pub fn routes(&self) -> &[NativeHttp1RouteProxyRoute] {
        &self.routes
    }

    pub fn fallback(&self) -> Option<&NativeHttp1Proxy> {
        self.fallback.as_ref()
    }
}

impl NativeHttp1RouteProxyRoute {
    pub fn exact(path: impl Into<String>, methods: Vec<String>, proxy: NativeHttp1Proxy) -> Self {
        Self {
            methods,
            matcher: NativeHttp1RouteMatcher::Exact(path.into()),
            strip_prefix: None,
            rewrite_prefix: None,
            max_request_body_bytes: None,
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            action: NativeHttp1RouteAction::Proxy(proxy),
        }
    }

    pub fn prefix(path: impl Into<String>, methods: Vec<String>, proxy: NativeHttp1Proxy) -> Self {
        Self {
            methods,
            matcher: NativeHttp1RouteMatcher::Prefix(path.into()),
            strip_prefix: None,
            rewrite_prefix: None,
            max_request_body_bytes: None,
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            action: NativeHttp1RouteAction::Proxy(proxy),
        }
    }

    pub fn fallback(proxy: NativeHttp1Proxy) -> Self {
        Self {
            methods: Vec::new(),
            matcher: NativeHttp1RouteMatcher::Fallback,
            strip_prefix: None,
            rewrite_prefix: None,
            max_request_body_bytes: None,
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            action: NativeHttp1RouteAction::Proxy(proxy),
        }
    }

    pub fn exact_redirect(
        path: impl Into<String>,
        methods: Vec<String>,
        to: impl Into<String>,
        status: u16,
    ) -> Self {
        Self {
            methods,
            matcher: NativeHttp1RouteMatcher::Exact(path.into()),
            strip_prefix: None,
            rewrite_prefix: None,
            max_request_body_bytes: None,
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            action: NativeHttp1RouteAction::Redirect(NativeHttp1RouteRedirect {
                to: to.into(),
                status,
            }),
        }
    }

    pub fn prefix_redirect(
        path: impl Into<String>,
        methods: Vec<String>,
        to: impl Into<String>,
        status: u16,
    ) -> Self {
        Self {
            methods,
            matcher: NativeHttp1RouteMatcher::Prefix(path.into()),
            strip_prefix: None,
            rewrite_prefix: None,
            max_request_body_bytes: None,
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            action: NativeHttp1RouteAction::Redirect(NativeHttp1RouteRedirect {
                to: to.into(),
                status,
            }),
        }
    }

    pub fn prefix_static_web(
        path: impl Into<String>,
        methods: Vec<String>,
        web: NativeHttp1StaticWeb,
    ) -> Self {
        Self {
            methods,
            matcher: NativeHttp1RouteMatcher::Prefix(path.into()),
            strip_prefix: None,
            rewrite_prefix: None,
            max_request_body_bytes: None,
            response_headers: NativeRouteResponseHeaderPolicy::default(),
            action: NativeHttp1RouteAction::StaticWeb(web),
        }
    }

    pub fn from_config(
        route: &fluxheim_config::RouteConfig,
        proxy: Option<NativeHttp1Proxy>,
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        if route.path_regex.is_some() {
            return Err(NativeHttp1RouteProxyConfigError::RegexRoute);
        }
        if route.rewrite_template.is_some() {
            return Err(NativeHttp1RouteProxyConfigError::RewriteTemplate);
        }
        let matcher = if let Some(path) = &route.path_exact {
            NativeHttp1RouteMatcher::Exact(path.clone())
        } else if let Some(path) = &route.path_prefix {
            NativeHttp1RouteMatcher::Prefix(path.clone())
        } else if route.fallback {
            NativeHttp1RouteMatcher::Fallback
        } else {
            return Err(NativeHttp1RouteProxyConfigError::MissingRouteAction);
        };
        let action = if let Some(redirect) = &route.redirect {
            NativeHttp1RouteAction::Redirect(NativeHttp1RouteRedirect {
                to: redirect.to.clone(),
                status: redirect.status,
            })
        } else if let Some(web) = route.web.as_ref().filter(|web| web.enabled()) {
            NativeHttp1RouteAction::StaticWeb(
                NativeHttp1StaticWeb::from_config(web)
                    .map_err(|_| NativeHttp1RouteProxyConfigError::StaticWeb)?
                    .ok_or(NativeHttp1RouteProxyConfigError::MissingRouteAction)?,
            )
        } else {
            NativeHttp1RouteAction::Proxy(
                proxy.ok_or(NativeHttp1RouteProxyConfigError::MissingRouteAction)?,
            )
        };
        Ok(Self {
            methods: route.methods.clone(),
            matcher,
            strip_prefix: route.strip_prefix.clone(),
            rewrite_prefix: route.rewrite_prefix.clone(),
            max_request_body_bytes: route.max_request_body_bytes.map(|bytes| bytes.as_u64()),
            response_headers: NativeRouteResponseHeaderPolicy::from_overlay(
                &route.headers.response,
            ),
            action,
        })
    }

    pub fn with_strip_prefix(mut self, strip_prefix: impl Into<String>) -> Self {
        self.strip_prefix = Some(strip_prefix.into());
        self
    }

    pub fn with_rewrite_prefix(mut self, rewrite_prefix: impl Into<String>) -> Self {
        self.rewrite_prefix = Some(rewrite_prefix.into());
        self
    }

    pub const fn with_max_request_body_bytes(mut self, max_request_body_bytes: u64) -> Self {
        self.max_request_body_bytes = Some(max_request_body_bytes);
        self
    }

    pub fn with_response_header_policy(
        mut self,
        response_headers: &ResponseHeaderPolicyOverlayConfig,
    ) -> Self {
        self.response_headers = NativeRouteResponseHeaderPolicy::from_overlay(response_headers);
        self
    }

    pub fn proxy(&self) -> Option<&NativeHttp1Proxy> {
        match &self.action {
            NativeHttp1RouteAction::Proxy(proxy) => Some(proxy),
            NativeHttp1RouteAction::Redirect(_) | NativeHttp1RouteAction::StaticWeb(_) => None,
        }
    }

    pub fn is_redirect(&self) -> bool {
        matches!(self.action, NativeHttp1RouteAction::Redirect(_))
    }

    pub fn is_static_web(&self) -> bool {
        matches!(self.action, NativeHttp1RouteAction::StaticWeb(_))
    }
}

impl NativeHttp1Handler for NativeHttp1RouteProxy {
    fn handle<'a>(
        &'a self,
        request: NativeHttp1Request,
    ) -> Pin<Box<dyn Future<Output = NativeHttp1Response> + Send + 'a>> {
        Box::pin(async move {
            let Some((path, query)) = request_path_and_query(&request) else {
                return NativeHttp1Response::new(400, "Bad Request", b"bad request\n")
                    .close_connection();
            };
            let route = self.select_route(&request.method, &path);
            let Some(route_or_fallback) = route
                .map(RouteOrFallback::Route)
                .or_else(|| self.fallback.as_ref().map(RouteOrFallback::Fallback))
            else {
                return NativeHttp1Response::new(404, "Not Found", b"not found\n")
                    .close_connection();
            };
            let request = match route_or_fallback.rewrite_request(request, &path, query.as_deref())
            {
                Some(request) => request,
                None => {
                    return NativeHttp1Response::new(400, "Bad Request", b"bad request\n")
                        .close_connection();
                }
            };
            if route_or_fallback.request_body_too_large(&request) {
                return NativeHttp1Response::new(413, "Payload Too Large", b"payload too large\n")
                    .close_connection();
            }
            match route_or_fallback {
                RouteOrFallback::Route(route) => route.handle(request).await,
                RouteOrFallback::Fallback(proxy) => proxy.handle(request).await,
            }
        })
    }
}

#[derive(Clone, Copy)]
enum RouteOrFallback<'a> {
    Route(&'a NativeHttp1RouteProxyRoute),
    Fallback(&'a NativeHttp1Proxy),
}

impl<'a> RouteOrFallback<'a> {
    fn rewrite_request(
        self,
        request: NativeHttp1Request,
        path: &str,
        query: Option<&str>,
    ) -> Option<NativeHttp1Request> {
        match self {
            Self::Route(route) => rewrite_route_request(request, route, path, query),
            Self::Fallback(_) => Some(request),
        }
    }

    fn request_body_too_large(self, request: &NativeHttp1Request) -> bool {
        match self {
            Self::Route(route) => route
                .max_request_body_bytes
                .is_some_and(|limit| (request.body.len() as u64) > limit),
            Self::Fallback(_) => false,
        }
    }
}

impl NativeHttp1RouteProxy {
    fn select_route(&self, method: &str, path: &str) -> Option<&NativeHttp1RouteProxyRoute> {
        let mut fallback = None;
        let mut best_prefix = None;
        for route in &self.routes {
            if !route_method_matches(&route.methods, method) {
                continue;
            }
            match &route.matcher {
                NativeHttp1RouteMatcher::Exact(exact) if path == exact => return Some(route),
                NativeHttp1RouteMatcher::Prefix(prefix)
                    if route_prefix_matches_path(prefix, path) =>
                {
                    if best_prefix
                        .map(|best: &NativeHttp1RouteProxyRoute| {
                            route.prefix_len() > best.prefix_len()
                        })
                        .unwrap_or(true)
                    {
                        best_prefix = Some(route);
                    }
                }
                NativeHttp1RouteMatcher::Fallback => fallback = Some(route),
                _ => {}
            }
        }
        best_prefix.or(fallback)
    }
}

impl NativeHttp1RouteProxyRoute {
    fn prefix_len(&self) -> usize {
        match &self.matcher {
            NativeHttp1RouteMatcher::Prefix(prefix) => prefix.len(),
            _ => 0,
        }
    }

    async fn handle(&self, request: NativeHttp1Request) -> NativeHttp1Response {
        let mut response = match &self.action {
            NativeHttp1RouteAction::Proxy(proxy) => proxy.handle(request).await,
            NativeHttp1RouteAction::Redirect(redirect) => redirect_response(&request, redirect),
            NativeHttp1RouteAction::StaticWeb(web) => {
                let Some((path, _)) = request_path_and_query(&request) else {
                    return NativeHttp1Response::new(400, "Bad Request", b"bad request\n")
                        .close_connection();
                };
                web.handle(&request, &path)
            }
        };
        self.response_headers.apply(&mut response);
        response
    }
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

fn rewrite_route_request(
    mut request: NativeHttp1Request,
    route: &NativeHttp1RouteProxyRoute,
    path: &str,
    query: Option<&str>,
) -> Option<NativeHttp1Request> {
    let Some(strip_prefix) = route.strip_prefix.as_deref() else {
        return Some(request);
    };
    let suffix = route_strip_prefix_suffix(strip_prefix, path)?;
    let rewritten_path = if let Some(rewrite_prefix) = route.rewrite_prefix.as_deref() {
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

fn redirect_response(
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

fn redirect_reason(status: u16) -> &'static str {
    match status {
        301 => "Moved Permanently",
        302 => "Found",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        _ => "Redirect",
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

    let location = redirect
        .to
        .replace("{uri}", &uri)
        .replace("{path}", &path)
        .replace("{query}", query.as_deref().unwrap_or_default());
    valid_redirect_location(&location).then_some(location)
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
    !path.contains("//") && !path.split('/').any(|segment| matches!(segment, "." | ".."))
}

impl NativeRouteResponseHeaderPolicy {
    fn from_overlay(overlay: &ResponseHeaderPolicyOverlayConfig) -> Self {
        let mut policy = Self {
            enabled: overlay.enabled.unwrap_or(true),
            unset: overlay.effective_unset(),
            set: overlay.effective_set().into_iter().collect(),
            append: flatten_append_headers(&overlay.append),
        };
        policy.apply_standard_headers(overlay);
        policy
    }

    fn apply_standard_headers(&mut self, overlay: &ResponseHeaderPolicyOverlayConfig) {
        if let Some(value) = &overlay.hsts {
            self.set_optional_header(
                "strict-transport-security",
                value.as_ref().and_then(|hsts| hsts.header_value()),
            );
        }
        if let Some(value) = &overlay.strict_transport_security {
            self.set_optional_header("strict-transport-security", value.clone());
        }
        if let Some(value) = &overlay.content_security_policy {
            self.set_optional_header("content-security-policy", value.clone());
        }
        if let Some(value) = &overlay.x_content_type_options {
            self.set_optional_header("x-content-type-options", value.clone());
        }
        if let Some(value) = &overlay.x_frame_options {
            self.set_optional_header("x-frame-options", value.clone());
        }
        if let Some(value) = &overlay.referrer_policy {
            self.set_optional_header("referrer-policy", value.clone());
        }
    }

    fn set_optional_header(&mut self, name: &str, value: Option<String>) {
        if let Some(value) = value {
            self.set.push((name.to_owned(), value));
        } else {
            self.unset.push(name.to_owned());
        }
    }

    fn apply(&self, response: &mut NativeHttp1Response) {
        if !self.enabled {
            return;
        }
        for name in &self.unset {
            response.remove_header(name);
        }
        for (name, value) in &self.set {
            response.remove_header(name);
            response.push_header(name.clone(), value.clone());
        }
        for (name, value) in &self.append {
            response.push_header(name.clone(), value.clone());
        }
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
