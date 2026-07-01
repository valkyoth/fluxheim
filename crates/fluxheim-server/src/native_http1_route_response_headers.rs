use fluxheim_config::{
    HeaderValues, ResponseHeaderPolicyConfig, ResponseHeaderPolicyOverlayConfig,
    ResponseHeaderRewriteConfig,
};
use fluxheim_headers::{rewrite_header_prefix, rewrite_refresh_url, rewrite_set_cookie_value};

use crate::NativeHttp1Response;

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct NativeRouteResponseHeaderPolicy {
    enabled: bool,
    unset: Vec<String>,
    set: Vec<(String, String)>,
    append: Vec<(String, String)>,
    rewrite: ResponseHeaderRewriteConfig,
}

impl NativeRouteResponseHeaderPolicy {
    pub(crate) fn from_policy(policy: &ResponseHeaderPolicyConfig) -> Self {
        let mut native = Self {
            enabled: policy.enabled,
            unset: policy.effective_unset(),
            set: policy.effective_set().into_iter().collect(),
            append: flatten_append_headers(&policy.append),
            rewrite: policy.rewrite.clone(),
        };
        native.apply_standard_headers_from_policy(policy);
        native
    }

    pub(crate) fn from_overlay(overlay: &ResponseHeaderPolicyOverlayConfig) -> Self {
        let mut policy = Self {
            enabled: overlay.enabled.unwrap_or(true),
            unset: overlay.effective_unset(),
            set: overlay.effective_set().into_iter().collect(),
            append: flatten_append_headers(&overlay.append),
            rewrite: overlay.rewrite.clone(),
        };
        policy.apply_standard_headers(overlay);
        policy
    }

    fn apply_standard_headers_from_policy(&mut self, policy: &ResponseHeaderPolicyConfig) {
        if let Some(value) = &policy.strict_transport_security {
            self.set_optional_header("strict-transport-security", Some(value.clone()));
        } else if let Some(hsts) = &policy.hsts
            && let Some(value) = hsts.header_value()
        {
            self.set_optional_header("strict-transport-security", Some(value));
        }
        if let Some(value) = &policy.content_security_policy {
            self.set_optional_header("content-security-policy", Some(value.clone()));
        }
        if let Some(value) = &policy.x_content_type_options {
            self.set_optional_header("x-content-type-options", Some(value.clone()));
        }
        if let Some(value) = &policy.x_frame_options {
            self.set_optional_header("x-frame-options", Some(value.clone()));
        }
        if let Some(value) = &policy.referrer_policy {
            self.set_optional_header("referrer-policy", Some(value.clone()));
        }
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

    pub(crate) fn apply(&self, response: &mut NativeHttp1Response) {
        if !self.enabled {
            return;
        }
        apply_response_rewrites(response, &self.rewrite);
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

fn apply_response_rewrites(
    response: &mut NativeHttp1Response,
    rewrite: &ResponseHeaderRewriteConfig,
) {
    rewrite_response_header_values(
        response,
        "location",
        &rewrite.location,
        rewrite_header_prefix,
    );
    rewrite_response_header_values(response, "refresh", &rewrite.refresh, rewrite_refresh_url);
    rewrite_set_cookie_header_values(response, rewrite);
}

fn rewrite_response_header_values(
    response: &mut NativeHttp1Response,
    name: &'static str,
    rules: &[fluxheim_config::ResponseHeaderRewriteRuleConfig],
    rewrite_value: fn(&str, &[fluxheim_config::ResponseHeaderRewriteRuleConfig]) -> Option<String>,
) {
    if rules.is_empty() {
        return;
    }
    let mut changed = false;
    let mut rewritten = Vec::with_capacity(response.headers().len());
    for (header_name, header_value) in response.headers() {
        if header_name.eq_ignore_ascii_case(name)
            && let Some(value) = rewrite_value(header_value, rules)
        {
            rewritten.push((header_name.clone(), value));
            changed = true;
        } else {
            rewritten.push((header_name.clone(), header_value.clone()));
        }
    }
    if changed {
        replace_response_headers(response, rewritten);
    }
}

fn rewrite_set_cookie_header_values(
    response: &mut NativeHttp1Response,
    rewrite: &ResponseHeaderRewriteConfig,
) {
    if rewrite.cookie_domain.is_empty() && rewrite.cookie_path.is_empty() {
        return;
    }
    let mut changed = false;
    let mut rewritten = Vec::with_capacity(response.headers().len());
    for (header_name, header_value) in response.headers() {
        if header_name.eq_ignore_ascii_case("set-cookie")
            && let Some(value) = rewrite_set_cookie_value(header_value, rewrite)
        {
            rewritten.push((header_name.clone(), value));
            changed = true;
        } else {
            rewritten.push((header_name.clone(), header_value.clone()));
        }
    }
    if changed {
        replace_response_headers(response, rewritten);
    }
}

fn replace_response_headers(response: &mut NativeHttp1Response, headers: Vec<(String, String)>) {
    let names = response
        .headers()
        .iter()
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    for name in names {
        response.remove_header(&name);
    }
    for (name, value) in headers {
        response.push_header(name, value);
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
