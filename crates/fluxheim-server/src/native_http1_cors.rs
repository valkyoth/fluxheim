use fluxheim_config::{CorsPolicyConfig, config_header_cors::valid_cors_origin};

use crate::{NativeHttp1Request, NativeHttp1Response};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct NativeCorsPolicy {
    enabled: bool,
    allow_origins: Vec<String>,
    allow_methods: Vec<String>,
    allow_headers: Vec<String>,
    expose_headers: Vec<String>,
    allow_credentials: bool,
    max_age_secs: Option<u64>,
}

impl NativeCorsPolicy {
    pub(crate) fn from_config(config: &CorsPolicyConfig) -> Self {
        Self {
            enabled: config.enabled,
            allow_origins: config.allow_origins.clone(),
            allow_methods: config.allow_methods.clone(),
            allow_headers: config.allow_headers.clone(),
            expose_headers: config.expose_headers.clone(),
            allow_credentials: config.allow_credentials,
            max_age_secs: config.max_age_secs,
        }
    }

    pub(crate) const fn enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn preflight_response(
        &self,
        request: &NativeHttp1Request,
    ) -> Option<NativeHttp1Response> {
        if !self.enabled || !request.method.eq_ignore_ascii_case("OPTIONS") {
            return None;
        }
        let requested_method = single_request_header(request, "access-control-request-method")?;
        let origin = match self.allowed_origin(request) {
            Some(origin) => origin,
            None => return Some(cors_rejection()),
        };
        if !self
            .allow_methods
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(requested_method))
        {
            return Some(cors_rejection());
        }
        let requested_headers = match requested_header_names(request) {
            Some(headers) => headers,
            None => return Some(cors_rejection()),
        };
        if requested_headers.iter().any(|requested| {
            !self
                .allow_headers
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(requested))
        }) {
            return Some(cors_rejection());
        }

        let mut response = NativeHttp1Response::new(204, "No Content", Vec::new());
        self.apply_preflight_headers(&mut response, origin);
        Some(response)
    }

    pub(crate) fn reapply_preflight_headers(
        &self,
        request: &NativeHttp1Request,
        response: &mut NativeHttp1Response,
    ) -> bool {
        let Some(origin) = self.allowed_origin(request) else {
            return false;
        };
        self.apply_preflight_headers(response, origin);
        true
    }

    fn apply_preflight_headers(&self, response: &mut NativeHttp1Response, origin: &str) {
        for name in [
            "access-control-allow-methods",
            "access-control-allow-headers",
            "access-control-max-age",
        ] {
            response.remove_header(name);
        }
        self.apply_owned_headers(response, Some(origin));
        set_response_header(
            response,
            "access-control-allow-methods",
            self.allow_methods.join(", "),
        );
        if !self.allow_headers.is_empty() {
            set_response_header(
                response,
                "access-control-allow-headers",
                self.allow_headers.join(", "),
            );
        }
        if let Some(max_age_secs) = self.max_age_secs {
            set_response_header(response, "access-control-max-age", max_age_secs.to_string());
        }
        ensure_vary_tokens(
            response,
            &[
                "Origin",
                "Access-Control-Request-Method",
                "Access-Control-Request-Headers",
            ],
        );
    }

    pub(crate) fn apply_response(
        &self,
        request: &NativeHttp1Request,
        response: &mut NativeHttp1Response,
    ) {
        let origin = self.response_origin(request);
        self.apply_response_origin(origin.as_deref(), response);
    }

    pub(crate) fn response_origin(&self, request: &NativeHttp1Request) -> Option<String> {
        if !self.enabled
            || !self
                .allow_methods
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(&request.method))
        {
            return None;
        }
        self.allowed_origin(request).map(str::to_owned)
    }

    pub(crate) fn apply_response_origin(
        &self,
        origin: Option<&str>,
        response: &mut NativeHttp1Response,
    ) {
        if !self.enabled {
            return;
        }
        self.apply_owned_headers(response, origin);
        if !self.allow_origins.iter().any(|origin| origin == "*") {
            ensure_vary_tokens(response, &["Origin"]);
        }
    }

    fn allowed_origin<'a>(&self, request: &'a NativeHttp1Request) -> Option<&'a str> {
        let origin = single_request_header(request, "origin")?;
        if !valid_cors_origin(origin) {
            return None;
        }
        if self.allow_origins.iter().any(|allowed| allowed == "*") {
            return Some("*");
        }
        self.allow_origins
            .iter()
            .any(|allowed| allowed.eq_ignore_ascii_case(origin))
            .then_some(origin)
    }

    fn apply_owned_headers(&self, response: &mut NativeHttp1Response, origin: Option<&str>) {
        for name in [
            "access-control-allow-origin",
            "access-control-allow-credentials",
            "access-control-expose-headers",
            "access-control-allow-methods",
            "access-control-allow-headers",
            "access-control-max-age",
            "access-control-allow-private-network",
        ] {
            response.remove_header(name);
        }
        let Some(origin) = origin else {
            return;
        };
        set_response_header(response, "access-control-allow-origin", origin.to_owned());
        if self.allow_credentials {
            set_response_header(
                response,
                "access-control-allow-credentials",
                "true".to_owned(),
            );
        }
        if !self.expose_headers.is_empty() {
            set_response_header(
                response,
                "access-control-expose-headers",
                self.expose_headers.join(", "),
            );
        }
    }
}

pub(crate) fn cors_preflight_requested_method(request: &NativeHttp1Request) -> Option<&str> {
    request
        .method
        .eq_ignore_ascii_case("OPTIONS")
        .then(|| single_request_header(request, "access-control-request-method"))
        .flatten()
}

fn requested_header_names(request: &NativeHttp1Request) -> Option<Vec<&str>> {
    let values = request
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("access-control-request-headers"))
        .map(|(_, value)| value.as_str())
        .collect::<Vec<_>>();
    let mut headers = Vec::new();
    for value in values {
        for name in value.split(',').map(str::trim) {
            if name.is_empty()
                || !fluxheim_config::config_header_validation::valid_http_header_name(name)
            {
                return None;
            }
            if !headers
                .iter()
                .any(|existing: &&str| existing.eq_ignore_ascii_case(name))
            {
                headers.push(name);
            }
        }
    }
    Some(headers)
}

fn single_request_header<'a>(request: &'a NativeHttp1Request, name: &str) -> Option<&'a str> {
    let mut values = request
        .headers
        .iter()
        .filter(|(header_name, value)| {
            header_name.eq_ignore_ascii_case(name) && !value.trim().is_empty()
        })
        .map(|(_, value)| value.trim());
    let first = values.next()?;
    values.next().is_none().then_some(first)
}

fn ensure_vary_tokens(response: &mut NativeHttp1Response, required: &[&str]) {
    let mut values = response
        .headers()
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("vary"))
        .flat_map(|(_, value)| value.split(','))
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if values.iter().any(|value| value == "*") {
        return;
    }
    for required in required {
        if !values
            .iter()
            .any(|value| value.eq_ignore_ascii_case(required))
        {
            values.push((*required).to_owned());
        }
    }
    set_response_header(response, "vary", values.join(", "));
}

fn set_response_header(response: &mut NativeHttp1Response, name: &str, value: String) {
    response.remove_header(name);
    response.push_header(name.to_owned(), value);
}

fn cors_rejection() -> NativeHttp1Response {
    NativeHttp1Response::new(403, "Forbidden", b"CORS request denied\n".to_vec()).close_connection()
}
