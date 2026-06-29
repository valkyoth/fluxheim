use std::io;
use std::time::Duration;

use crate::http_types::PingoraRequestHeader as RequestHeader;
use bytes::Bytes;
use fluxheim_headers::join_header_values_with_separator;
use sanitization::SecretString;

use crate::flux_error::{FluxError, FluxResult};

#[derive(Debug)]
pub(crate) struct AuthRequestInput {
    pub(crate) headers: Vec<(String, SecretString)>,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct AuthRequestContext<'a> {
    pub(crate) original_uri: &'a str,
    pub(crate) forwarded_for: Option<&'a str>,
    pub(crate) forwarded_host: Option<&'a str>,
    pub(crate) forwarded_proto: &'a str,
}

#[derive(Debug)]
pub(crate) enum AuthRequestDecision {
    Allow { headers: Vec<(String, String)> },
    Deny { status: u16, body: Bytes },
}

pub(crate) fn auth_request_input(
    request: &RequestHeader,
    auth: &crate::config::AuthRequestConfig,
    context: AuthRequestContext<'_>,
) -> AuthRequestInput {
    let mut headers = Vec::new();
    for name in &auth.forward_headers {
        if let Some(value) = trusted_context_header_value(name, context)
            .or_else(|| request_header_values_joined(request, name))
        {
            headers.push((name.clone(), SecretString::from_string(value)));
        }
    }
    AuthRequestInput { headers }
}

pub(crate) fn fetch_auth_request_decision(
    auth: &crate::config::AuthRequestConfig,
    input: &AuthRequestInput,
) -> FluxResult<AuthRequestDecision> {
    let url = auth
        .url
        .as_deref()
        .ok_or(FluxError::InvalidInput("enabled auth_request requires url"))?;
    let timeout = Duration::from_secs(
        auth.connect_timeout_secs
            .saturating_add(auth.read_timeout_secs),
    );
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .into();
    let mut builder = agent.get(url).header("cache-control", "no-store");
    for (name, value) in &input.headers {
        builder = value
            .try_with_secret(|value| builder.header(name.as_str(), value))
            .map_err(|error| {
                FluxError::io(
                    "auth_request forwarded header secret",
                    io::Error::new(io::ErrorKind::InvalidData, error),
                )
            })?;
    }
    let mut response = builder.call().map_err(auth_request_io_error)?;
    let status = response.status().as_u16();
    let body = response
        .body_mut()
        .with_config()
        .limit(auth.max_response_bytes.as_u64().saturating_add(1))
        .read_to_vec()
        .map_err(auth_request_io_error)?;
    if body.len() as u64 > auth.max_response_bytes.as_u64() {
        return Err(FluxError::io(
            "auth_request response exceeds configured body limit",
            io::Error::new(
                io::ErrorKind::InvalidData,
                "auth_request response exceeds configured body limit",
            ),
        ));
    }
    if (200..300).contains(&status) {
        return Ok(AuthRequestDecision::Allow {
            headers: auth_response_allowed_headers(auth, &response),
        });
    }
    let status = if (400..600).contains(&status) {
        status
    } else {
        500
    };
    Ok(AuthRequestDecision::Deny {
        status,
        body: Bytes::from(body),
    })
}

fn auth_response_allowed_headers(
    auth: &crate::config::AuthRequestConfig,
    response: &ureq::http::Response<ureq::Body>,
) -> Vec<(String, String)> {
    response
        .headers()
        .iter()
        .filter_map(|(name, value)| {
            if !auth
                .allow_response_headers
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(name.as_str()))
            {
                return None;
            }
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_ascii_lowercase(), value.to_owned()))
        })
        .collect()
}

fn auth_request_io_error(error: impl std::fmt::Display) -> FluxError {
    FluxError::io(
        "auth_request HTTP subrequest",
        io::Error::other(error.to_string()),
    )
}

fn trusted_context_header_value(name: &str, context: AuthRequestContext<'_>) -> Option<String> {
    if name.eq_ignore_ascii_case("x-original-uri")
        || name.eq_ignore_ascii_case("x-forwarded-uri")
        || name.eq_ignore_ascii_case("x-auth-request-redirect")
    {
        return Some(context.original_uri.to_owned());
    }
    if name.eq_ignore_ascii_case("x-forwarded-for") || name.eq_ignore_ascii_case("x-real-ip") {
        return context.forwarded_for.map(str::to_owned);
    }
    if name.eq_ignore_ascii_case("x-forwarded-host") {
        return context.forwarded_host.map(str::to_owned);
    }
    if name.eq_ignore_ascii_case("x-forwarded-proto") {
        return Some(context.forwarded_proto.to_owned());
    }
    None
}

fn request_header_values_joined(request: &RequestHeader, name: &str) -> Option<String> {
    let separator = if name.eq_ignore_ascii_case("cookie") {
        "; "
    } else {
        ", "
    };
    join_header_values_with_separator(
        request
            .headers
            .get_all(name)
            .iter()
            .filter_map(|value| value.to_str().ok()),
        separator,
    )
}
