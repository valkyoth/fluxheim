use fluxheim_config::config_header_hardening::reporting_endpoints_header_value;
use fluxheim_config::{
    HeaderPolicyConfig, HeaderValues, ResponseHardeningProfile, ResponseHeaderPolicyConfig,
    ResponseHeaderPolicyOverlayConfig, ResponseHeaderRewriteConfig, ResponseMetadataConfig,
};
use fluxheim_headers::{rewrite_header_prefix, rewrite_refresh_url, rewrite_set_cookie_value};

use crate::NativeHttp1Request;
use crate::NativeHttp1Response;
use crate::native_http1_cors::NativeCorsPolicy;
use crate::native_http1_response_metadata::{
    apply_native_digest_metadata, apply_native_status_metadata,
};

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub(crate) struct NativeRouteResponseHeaderPolicy {
    enabled: bool,
    unset: Vec<String>,
    set: Vec<(String, String)>,
    append: Vec<(String, String)>,
    rewrite: ResponseHeaderRewriteConfig,
    cors: NativeCorsPolicy,
    metadata: ResponseMetadataConfig,
}

impl NativeRouteResponseHeaderPolicy {
    pub(crate) fn from_header_policy(headers: &HeaderPolicyConfig) -> Self {
        Self::from_policy_and_cors(&headers.response, &headers.cors)
    }

    fn from_policy_and_cors(
        policy: &ResponseHeaderPolicyConfig,
        cors: &fluxheim_config::CorsPolicyConfig,
    ) -> Self {
        let mut native = Self {
            enabled: policy.enabled,
            unset: Vec::new(),
            set: Vec::new(),
            append: Vec::new(),
            rewrite: policy.rewrite.clone(),
            cors: NativeCorsPolicy::from_config(cors),
            metadata: policy.metadata.clone(),
        };
        native.apply_hardening_profile(policy.hardening.profile);
        native.apply_standard_headers_from_policy(policy);
        native.apply_explicit_mutations(
            policy.effective_unset(),
            policy.effective_set(),
            &policy.append,
        );
        native
    }

    pub(crate) fn from_overlay(overlay: &ResponseHeaderPolicyOverlayConfig) -> Self {
        let mut policy = Self {
            enabled: overlay.enabled.unwrap_or(true),
            unset: Vec::new(),
            set: Vec::new(),
            append: Vec::new(),
            rewrite: overlay.rewrite.clone(),
            cors: NativeCorsPolicy::default(),
            metadata: ResponseMetadataConfig::default(),
        };
        policy.metadata.apply_overlay(&overlay.metadata);
        if let Some(hardening) = &overlay.hardening {
            policy.apply_hardening_profile(hardening.profile);
        }
        policy.apply_standard_headers(overlay);
        policy.apply_explicit_mutations(
            overlay.effective_unset(),
            overlay.effective_set(),
            &overlay.append,
        );
        policy
    }

    fn apply_hardening_profile(&mut self, profile: ResponseHardeningProfile) {
        if profile == ResponseHardeningProfile::Off {
            return;
        }
        self.unset_header("server");
        self.set_header(
            "permissions-policy",
            "camera=(), geolocation=(), microphone=(), payment=(), usb=()".to_owned(),
        );
        self.set_header("x-permitted-cross-domain-policies", "none".to_owned());
        if profile == ResponseHardeningProfile::CrossOriginIsolated {
            self.set_header("cross-origin-opener-policy", "same-origin".to_owned());
            self.set_header("cross-origin-resource-policy", "same-origin".to_owned());
            self.set_header("cross-origin-embedder-policy", "require-corp".to_owned());
        }
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
        if let Some(value) = &policy.content_security_policy_report_only {
            self.set_optional_header("content-security-policy-report-only", Some(value.clone()));
        }
        if let Some(value) = &policy.permissions_policy {
            self.set_optional_header(
                "permissions-policy",
                value.header_value().map(str::to_owned),
            );
        }
        if let Some(value) = policy.cross_origin_opener_policy {
            self.set_optional_header(
                "cross-origin-opener-policy",
                Some(value.header_value().to_owned()),
            );
        }
        if let Some(value) = policy.cross_origin_resource_policy {
            self.set_optional_header(
                "cross-origin-resource-policy",
                Some(value.header_value().to_owned()),
            );
        }
        if let Some(value) = policy.cross_origin_embedder_policy {
            self.set_optional_header(
                "cross-origin-embedder-policy",
                Some(value.header_value().to_owned()),
            );
        }
        if let Some(value) = policy.x_permitted_cross_domain_policies {
            self.set_optional_header(
                "x-permitted-cross-domain-policies",
                Some(value.header_value().to_owned()),
            );
        }
        if let Some(value) = reporting_endpoints_header_value(&policy.reporting_endpoints) {
            self.set_optional_header("reporting-endpoints", Some(value));
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
        if let Some(value) = &overlay.content_security_policy_report_only {
            self.set_optional_header("content-security-policy-report-only", value.clone());
        }
        if let Some(value) = &overlay.permissions_policy {
            self.set_optional_header(
                "permissions-policy",
                value
                    .as_ref()
                    .and_then(|value| value.header_value())
                    .map(str::to_owned),
            );
        }
        if let Some(value) = overlay.cross_origin_opener_policy {
            self.set_optional_header(
                "cross-origin-opener-policy",
                value.map(|value| value.header_value().to_owned()),
            );
        }
        if let Some(value) = overlay.cross_origin_resource_policy {
            self.set_optional_header(
                "cross-origin-resource-policy",
                value.map(|value| value.header_value().to_owned()),
            );
        }
        if let Some(value) = overlay.cross_origin_embedder_policy {
            self.set_optional_header(
                "cross-origin-embedder-policy",
                value.map(|value| value.header_value().to_owned()),
            );
        }
        if let Some(value) = overlay.x_permitted_cross_domain_policies {
            self.set_optional_header(
                "x-permitted-cross-domain-policies",
                value.map(|value| value.header_value().to_owned()),
            );
        }
        if let Some(endpoints) = &overlay.reporting_endpoints {
            self.set_optional_header(
                "reporting-endpoints",
                reporting_endpoints_header_value(endpoints),
            );
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
            self.set_header(name, value);
        } else {
            self.unset_header(name);
        }
    }

    fn set_header(&mut self, name: &str, value: String) {
        self.unset
            .retain(|existing| !existing.eq_ignore_ascii_case(name));
        self.set
            .retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
        self.set.push((name.to_owned(), value));
    }

    fn unset_header(&mut self, name: &str) {
        self.set
            .retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
        if !self
            .unset
            .iter()
            .any(|existing| existing.eq_ignore_ascii_case(name))
        {
            self.unset.push(name.to_owned());
        }
    }

    fn apply_explicit_mutations(
        &mut self,
        unset: Vec<String>,
        set: std::collections::BTreeMap<String, String>,
        append: &std::collections::BTreeMap<String, HeaderValues>,
    ) {
        for name in unset {
            self.unset_header(&name);
        }
        for (name, value) in set {
            self.set_header(&name, value);
        }
        self.append.extend(flatten_append_headers(append));
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
        apply_native_status_metadata(&self.metadata, response);
    }

    pub(crate) fn apply_for_request(
        &self,
        request: &NativeHttp1Request,
        response: &mut NativeHttp1Response,
    ) {
        self.apply(response);
        self.cors.apply_response(request, response);
    }

    pub(crate) fn apply_digests_for_method(
        &self,
        request_method: &str,
        response: &mut NativeHttp1Response,
    ) {
        if self.enabled {
            apply_native_digest_metadata(&self.metadata, request_method, response);
        }
    }

    pub(crate) fn cors_response_origin(&self, request: &NativeHttp1Request) -> Option<String> {
        self.cors.response_origin(request)
    }

    pub(crate) const fn cors_enabled(&self) -> bool {
        self.cors.enabled()
    }

    pub(crate) fn apply_with_cors_origin(
        &self,
        origin: Option<&str>,
        response: &mut NativeHttp1Response,
    ) {
        self.apply(response);
        self.cors.apply_response_origin(origin, response);
    }

    pub(crate) fn cors_preflight_response(
        &self,
        request: &NativeHttp1Request,
    ) -> Option<NativeHttp1Response> {
        let mut response = self.cors.preflight_response(request)?;
        self.apply(&mut response);
        if !self.cors.reapply_preflight_headers(request, &mut response) {
            return Some(
                NativeHttp1Response::new(403, "Forbidden", b"CORS request denied\n".to_vec())
                    .close_connection(),
            );
        }
        self.apply_digests_for_method(&request.method, &mut response);
        Some(response)
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
