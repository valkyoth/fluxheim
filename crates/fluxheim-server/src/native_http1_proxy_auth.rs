use std::sync::{Arc, OnceLock};
use std::time::Duration;

use sanitization::SecretString;

use crate::NativeHttp1Request;

const MAX_GLOBAL_AUTH_REQUESTS_IN_FLIGHT: usize = 256;
static GLOBAL_AUTH_REQUESTS_IN_FLIGHT: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();

#[derive(Clone, Debug)]
pub(crate) struct NativeAuthRequest {
    url: String,
    forward_headers: Vec<String>,
    allow_response_headers: Vec<String>,
    timeout: Duration,
    max_response_bytes: u64,
    max_in_flight: usize,
    inflight: Arc<tokio::sync::Semaphore>,
    global_inflight: Arc<tokio::sync::Semaphore>,
}

impl PartialEq for NativeAuthRequest {
    fn eq(&self, other: &Self) -> bool {
        self.url == other.url
            && self.forward_headers == other.forward_headers
            && self.allow_response_headers == other.allow_response_headers
            && self.timeout == other.timeout
            && self.max_response_bytes == other.max_response_bytes
            && self.max_in_flight == other.max_in_flight
    }
}

impl Eq for NativeAuthRequest {}

#[derive(Debug)]
pub(crate) enum NativeAuthRequestDecision {
    Allow {
        headers: Vec<(String, SecretString)>,
    },
    Deny {
        status: u16,
        body: Vec<u8>,
    },
}

#[derive(Debug)]
struct NativeAuthRequestInput {
    headers: Vec<(String, SecretString)>,
}

impl NativeAuthRequest {
    pub(crate) fn from_config(config: &fluxheim_config::AuthRequestConfig) -> Option<Self> {
        if !config.enabled {
            return None;
        }
        Some(Self {
            url: config.url.clone()?,
            forward_headers: config.forward_headers.clone(),
            allow_response_headers: config.allow_response_headers.clone(),
            timeout: Duration::from_secs(
                config
                    .connect_timeout_secs
                    .saturating_add(config.read_timeout_secs),
            ),
            max_response_bytes: config.max_response_bytes.as_u64(),
            max_in_flight: config.max_in_flight,
            inflight: Arc::new(tokio::sync::Semaphore::new(config.max_in_flight)),
            global_inflight: global_auth_request_inflight(),
        })
    }

    pub(crate) async fn authorize(
        &self,
        request: &NativeHttp1Request,
    ) -> std::io::Result<NativeAuthRequestDecision> {
        let auth = self.clone();
        let input = self.input(request);
        let service_permit = self.inflight.clone().try_acquire_owned().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "authorization service saturated",
            )
        })?;
        let global_permit = self
            .global_inflight
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                std::io::Error::new(
                    std::io::ErrorKind::WouldBlock,
                    "process-wide authorization capacity saturated",
                )
            })?;
        let blocking_permit = crate::blocking_work::try_acquire_request_blocking_work(
            crate::blocking_work::NativeBlockingWorkClass::Auth,
        )
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::WouldBlock,
                "process-wide request blocking-work capacity saturated",
            )
        })?;
        tokio::task::spawn_blocking(move || {
            let _permits = (service_permit, global_permit, blocking_permit);
            auth.fetch_decision(&input)
        })
        .await
        .map_err(|error| std::io::Error::other(error.to_string()))?
    }

    fn input(&self, request: &NativeHttp1Request) -> NativeAuthRequestInput {
        let mut headers = Vec::new();
        for name in &self.forward_headers {
            if let Some(value) = native_auth_context_header_value(name, request)
                .or_else(|| native_request_header_values_joined_for_auth(request, name))
            {
                headers.push((name.clone(), SecretString::from_string(value)));
            }
        }
        NativeAuthRequestInput { headers }
    }

    fn fetch_decision(
        &self,
        input: &NativeAuthRequestInput,
    ) -> std::io::Result<NativeAuthRequestDecision> {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .timeout_global(Some(self.timeout))
            .max_redirects(0)
            .http_status_as_error(false)
            .build()
            .into();
        let mut builder = agent.get(&self.url).header("cache-control", "no-store");
        for (name, value) in &input.headers {
            builder = value
                .try_with_secret(|value| builder.header(name.as_str(), value))
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
        }
        let mut response = builder
            .call()
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        let status = response.status().as_u16();
        if (200..300).contains(&status) {
            let body = zeroize::Zeroizing::new(
                response
                    .body_mut()
                    .with_config()
                    .limit(self.max_response_bytes.saturating_add(1))
                    .read_to_vec()
                    .map_err(|error| std::io::Error::other(error.to_string()))?,
            );
            if body.len() as u64 > self.max_response_bytes {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "auth_request response exceeds configured body limit",
                ));
            }
            return Ok(NativeAuthRequestDecision::Allow {
                headers: self.allowed_response_headers(&response),
            });
        }
        let body = response
            .body_mut()
            .with_config()
            .limit(self.max_response_bytes.saturating_add(1))
            .read_to_vec()
            .map_err(|error| std::io::Error::other(error.to_string()))?;
        if body.len() as u64 > self.max_response_bytes {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "auth_request response exceeds configured body limit",
            ));
        }
        let status = if (400..600).contains(&status) {
            status
        } else {
            500
        };
        Ok(NativeAuthRequestDecision::Deny { status, body })
    }

    fn allowed_response_headers(
        &self,
        response: &ureq::http::Response<ureq::Body>,
    ) -> Vec<(String, SecretString)> {
        response
            .headers()
            .iter()
            .filter_map(|(name, value)| {
                if !self
                    .allow_response_headers
                    .iter()
                    .any(|allowed| allowed.eq_ignore_ascii_case(name.as_str()))
                {
                    return None;
                }
                value.to_str().ok().map(|value| {
                    (
                        name.as_str().to_ascii_lowercase(),
                        SecretString::from_secret_str(value),
                    )
                })
            })
            .collect()
    }
}

fn global_auth_request_inflight() -> Arc<tokio::sync::Semaphore> {
    GLOBAL_AUTH_REQUESTS_IN_FLIGHT
        .get_or_init(|| {
            Arc::new(tokio::sync::Semaphore::new(
                MAX_GLOBAL_AUTH_REQUESTS_IN_FLIGHT,
            ))
        })
        .clone()
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use fluxheim_protocol::Http1Version;
    use zeroize::Zeroizing;

    #[test]
    fn auth_request_instances_share_process_wide_admission() {
        let config = fluxheim_config::AuthRequestConfig {
            enabled: true,
            url: Some("http://127.0.0.1:4180/auth".to_owned()),
            ..Default::default()
        };
        let first = NativeAuthRequest::from_config(&config).unwrap();
        let second = NativeAuthRequest::from_config(&config).unwrap();

        assert!(Arc::ptr_eq(&first.global_inflight, &second.global_inflight));
        assert_eq!(
            first.global_inflight.available_permits(),
            MAX_GLOBAL_AUTH_REQUESTS_IN_FLIGHT
        );
    }

    #[tokio::test]
    async fn process_wide_auth_admission_rejects_across_service_instances() {
        let config = fluxheim_config::AuthRequestConfig {
            enabled: true,
            url: Some("http://127.0.0.1:4180/auth".to_owned()),
            ..Default::default()
        };
        let shared = Arc::new(tokio::sync::Semaphore::new(1));
        let mut first = NativeAuthRequest::from_config(&config).unwrap();
        let mut second = NativeAuthRequest::from_config(&config).unwrap();
        first.global_inflight = Arc::clone(&shared);
        second.global_inflight = Arc::clone(&shared);
        let _occupied = first.global_inflight.clone().try_acquire_owned().unwrap();
        let request = NativeHttp1Request {
            method: "GET".to_owned(),
            peer_addr: None,
            local_addr: None,
            effective_client_addr: None,
            downstream_tls: false,
            tls_identity: None,
            geo_context: None,
            target: "/".to_owned(),
            version: Http1Version::Http11,
            headers: vec![("host".to_owned(), "app.test".to_owned())],
            body: Zeroizing::new(Vec::new()),
            trailers: Vec::new(),
        };

        let error = second.authorize(&request).await.unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);
        assert_eq!(second.inflight.available_permits(), second.max_in_flight);
    }
}

fn native_auth_context_header_value(name: &str, request: &NativeHttp1Request) -> Option<String> {
    if name.eq_ignore_ascii_case("x-original-uri")
        || name.eq_ignore_ascii_case("x-forwarded-uri")
        || name.eq_ignore_ascii_case("x-auth-request-redirect")
    {
        return Some(request.target.clone());
    }
    if name.eq_ignore_ascii_case("x-forwarded-for") || name.eq_ignore_ascii_case("x-real-ip") {
        #[cfg(not(feature = "privacy-mode"))]
        {
            return request.peer_addr.map(|peer| peer.ip().to_string());
        }
        #[cfg(feature = "privacy-mode")]
        {
            return None;
        }
    }
    if name.eq_ignore_ascii_case("x-forwarded-host") {
        return native_request_header_values(request, "host")
            .next()
            .map(str::to_owned);
    }
    if name.eq_ignore_ascii_case("x-forwarded-proto") {
        return Some(
            if request.downstream_tls {
                "https"
            } else {
                "http"
            }
            .to_owned(),
        );
    }
    None
}

pub(crate) fn apply_native_auth_request_headers(
    request: &mut NativeHttp1Request,
    headers: &[(String, SecretString)],
) {
    for (name, value) in headers {
        value
            .try_with_secret(|value| native_request_replace_header(request, name, value))
            .unwrap_or_else(|error| {
                log::error!(
                target: "fluxheim::auth_request",
                "auth_request response header application failed; internal secret lock poisoned, aborting to avoid inconsistent forwarded identity state: {error}"
            );
                std::process::abort();
            });
    }
}

fn native_request_replace_header(request: &mut NativeHttp1Request, name: &str, value: &str) {
    request
        .headers
        .retain(|(header_name, _)| !header_name.eq_ignore_ascii_case(name));
    request.headers.push((name.to_owned(), value.to_owned()));
}

pub(crate) fn native_auth_status_reason(status: u16) -> &'static str {
    match status {
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Forbidden",
    }
}

fn native_request_header_values<'a>(
    request: &'a NativeHttp1Request,
    name: &'a str,
) -> impl Iterator<Item = &'a str> {
    request
        .headers
        .iter()
        .filter(move |(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

fn native_request_header_values_joined_for_auth(
    request: &NativeHttp1Request,
    name: &str,
) -> Option<String> {
    let separator = if name.eq_ignore_ascii_case("cookie") {
        "; "
    } else {
        ", "
    };
    fluxheim_headers::join_header_values_with_separator(
        native_request_header_values(request, name).filter(|value| !value.trim().is_empty()),
        separator,
    )
}

#[cfg(test)]
mod tests {
    use super::apply_native_auth_request_headers;
    use crate::NativeHttp1Request;
    use fluxheim_protocol::Http1Version;
    use zeroize::Zeroizing;

    #[test]
    fn native_auth_request_headers_replace_existing_values() {
        let mut request = NativeHttp1Request {
            method: "GET".to_owned(),
            peer_addr: None,
            local_addr: None,
            effective_client_addr: None,
            downstream_tls: false,
            tls_identity: None,
            geo_context: None,
            target: "/asset.png".to_owned(),
            version: Http1Version::Http11,
            headers: vec![
                ("host".to_owned(), "auth.test".to_owned()),
                ("x-user-id".to_owned(), "attacker".to_owned()),
            ],
            body: Zeroizing::new(Vec::new()),
            trailers: Vec::new(),
        };
        let headers = vec![(
            "x-user-id".to_owned(),
            sanitization::SecretString::from_secret_str("user-123"),
        )];

        apply_native_auth_request_headers(&mut request, &headers);

        assert_eq!(
            request
                .headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("x-user-id"))
                .collect::<Vec<_>>(),
            vec![&("x-user-id".to_owned(), "user-123".to_owned())]
        );
    }
}
