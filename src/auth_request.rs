use std::io;
use std::time::Duration;

use crate::http_types::PingoraRequestHeader as RequestHeader;
use bytes::Bytes;
use zeroize::Zeroizing;

use crate::flux_error::{FluxError, FluxResult};

#[derive(Debug)]
pub(crate) struct AuthRequestInput {
    pub(crate) headers: Vec<(String, Zeroizing<String>)>,
}

#[derive(Debug)]
pub(crate) enum AuthRequestDecision {
    Allow { headers: Vec<(String, String)> },
    Deny { status: u16, body: Bytes },
}

pub(crate) fn auth_request_input(
    request: &RequestHeader,
    auth: &crate::config::AuthRequestConfig,
) -> AuthRequestInput {
    let mut headers = Vec::new();
    for name in &auth.forward_headers {
        if let Some(value) = request_header_values_joined(request, name) {
            headers.push((name.clone(), Zeroizing::new(value)));
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
        builder = builder.header(name.as_str(), value.as_str());
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

fn request_header_values_joined(request: &RequestHeader, name: &str) -> Option<String> {
    let mut values = request
        .headers
        .get_all(name)
        .iter()
        .filter_map(|value| value.to_str().ok());
    let first = values.next()?.to_owned();
    Some(values.fold(first, |mut joined, value| {
        joined.push_str(", ");
        joined.push_str(value);
        joined
    }))
}
