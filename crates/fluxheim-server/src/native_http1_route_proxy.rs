use std::future::Future;
use std::pin::Pin;

use fluxheim_common::path_safety::safe_forward_path;
use fluxheim_protocol::{
    Http1RequestTarget, http1_request_target, route_method_matches, route_prefix_matches_path,
    route_strip_prefix_suffix,
};

use crate::{NativeHttp1Handler, NativeHttp1Proxy, NativeHttp1Request, NativeHttp1Response};

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
    proxy: NativeHttp1Proxy,
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum NativeHttp1RouteMatcher {
    Exact(String),
    Prefix(String),
    Fallback,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeHttp1RouteProxyConfigError {
    MissingRouteAction,
    RegexRoute,
    RedirectRoute,
    RewriteTemplate,
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
            Self::RedirectRoute => {
                formatter.write_str("native route proxy does not yet support route redirects")
            }
            Self::RewriteTemplate => {
                formatter.write_str("native route proxy does not yet support rewrite_template")
            }
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
            proxy,
        }
    }

    pub fn prefix(path: impl Into<String>, methods: Vec<String>, proxy: NativeHttp1Proxy) -> Self {
        Self {
            methods,
            matcher: NativeHttp1RouteMatcher::Prefix(path.into()),
            strip_prefix: None,
            rewrite_prefix: None,
            proxy,
        }
    }

    pub fn fallback(proxy: NativeHttp1Proxy) -> Self {
        Self {
            methods: Vec::new(),
            matcher: NativeHttp1RouteMatcher::Fallback,
            strip_prefix: None,
            rewrite_prefix: None,
            proxy,
        }
    }

    pub fn from_config(
        route: &fluxheim_config::RouteConfig,
        proxy: NativeHttp1Proxy,
    ) -> Result<Self, NativeHttp1RouteProxyConfigError> {
        if route.path_regex.is_some() {
            return Err(NativeHttp1RouteProxyConfigError::RegexRoute);
        }
        if route.redirect.is_some() {
            return Err(NativeHttp1RouteProxyConfigError::RedirectRoute);
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
        Ok(Self {
            methods: route.methods.clone(),
            matcher,
            strip_prefix: route.strip_prefix.clone(),
            rewrite_prefix: route.rewrite_prefix.clone(),
            proxy,
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

    pub fn proxy(&self) -> &NativeHttp1Proxy {
        &self.proxy
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
            let Some(proxy) = route
                .map(NativeHttp1RouteProxyRoute::proxy)
                .or(self.fallback.as_ref())
            else {
                return NativeHttp1Response::new(404, "Not Found", b"not found\n")
                    .close_connection();
            };
            let request = if let Some(route) = route {
                match rewrite_route_request(request, route, &path, query.as_deref()) {
                    Some(request) => request,
                    None => {
                        return NativeHttp1Response::new(400, "Bad Request", b"bad request\n")
                            .close_connection();
                    }
                }
            } else {
                request
            };
            proxy.handle(request).await
        })
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
