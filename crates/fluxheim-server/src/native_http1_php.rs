#![allow(
    dead_code,
    reason = "native PHP-FPM request planning is staged before route runtime wiring"
)]

use std::io;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use fluxheim_config::PhpConfig;
use fluxheim_php_fpm::{PhpFpmPool, PhpRequestBody};
use fluxheim_protocol::{Http1RequestTarget, Http1Version, http1_request_target};

use crate::{NativeHttp1Request, NativeHttp1Response};

mod response;
pub(crate) use response::native_php_response_plan;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativePhpRequestPlan {
    pub(crate) script_name: String,
    pub(crate) path_info: String,
    pub(crate) script_filename: String,
    pub(crate) path_translated: Option<String>,
    pub(crate) params: Vec<(String, String)>,
    pub(crate) dropped_custom_params: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativePhpResponsePlan {
    pub(crate) response: NativeHttp1Response,
    pub(crate) intercept_status: Option<u16>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NativePhpScriptResolution {
    pub(crate) local_path: std::path::PathBuf,
    pub(crate) script_name: String,
    pub(crate) path_info: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum NativePhpScriptResolve {
    Execute(NativePhpScriptResolution),
    RedirectDirectorySlash,
    Decline,
    NotFound,
    Forbidden,
}

pub(crate) async fn native_php_request_body(
    request: &NativeHttp1Request,
    php: &PhpConfig,
) -> io::Result<fluxheim_php_fpm::PhpRequestBody> {
    if let Some(limit) = php.max_request_body_bytes
        && request.body.len() as u64 > limit.as_u64()
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "PHP request body exceeds configured limit",
        ));
    }
    let Some(threshold) = php.request_body_spool_threshold_bytes else {
        return Ok(fluxheim_php_fpm::PhpRequestBody::memory_zeroizing(
            request.body.clone(),
        ));
    };
    if request.body.len() as u64 <= threshold.as_u64() {
        return Ok(fluxheim_php_fpm::PhpRequestBody::memory_zeroizing(
            request.body.clone(),
        ));
    }
    let Some(spool_dir) = php.request_body_spool_dir.as_deref() else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "PHP request body spool directory is required",
        ));
    };
    let (path, mut file) = fluxheim_php_fpm::create_php_request_body_spool_file(spool_dir).await?;
    tokio::io::AsyncWriteExt::write_all(&mut file, &request.body).await?;
    tokio::io::AsyncWriteExt::flush(&mut file).await?;
    drop(file);
    Ok(fluxheim_php_fpm::PhpRequestBody::spooled(
        path,
        request.body.len(),
    ))
}

pub(crate) async fn native_php_execute_fpm(
    php: &PhpConfig,
    plan: &NativePhpRequestPlan,
    body: PhpRequestBody,
    pools: &[Arc<PhpFpmPool>],
    next_endpoint: &AtomicUsize,
) -> io::Result<NativePhpResponsePlan> {
    let endpoints = fluxheim_php_fpm::php_fpm_endpoints_from_config(&php.fpm);
    if endpoints.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "php-fpm socket, tcp, or tcp_upstreams is required",
        ));
    }

    let timeout = Duration::from_secs(php.request_timeout_secs);
    let connect_timeout = fluxheim_php_fpm::php_fpm_effective_connect_timeout(&php.fpm, timeout);
    let request_timeout = fluxheim_php_fpm::php_fpm_effective_request_timeout(&php.fpm, timeout);
    let max_retries = fluxheim_php_fpm::php_fpm_retry_attempts_for_endpoint_count(
        &php.fpm,
        native_php_request_method(plan).unwrap_or("GET"),
        endpoints.len(),
    );
    let retry_deadline = fluxheim_php_fpm::php_fpm_retry_deadline(php.fpm.retry_timeout_secs);
    let start_index = native_php_select_endpoint_index(next_endpoint, endpoints.len());
    let mut attempts = 0_u8;
    loop {
        let endpoint_index = (start_index + usize::from(attempts)) % endpoints.len();
        let result = fluxheim_php_fpm::execute_php_fpm_once(
            pools.get(endpoint_index).map(Arc::as_ref),
            &endpoints[endpoint_index],
            native_php_fastcgi_params(plan),
            &body,
            connect_timeout,
            request_timeout,
            php.max_response_bytes.as_u64(),
        )
        .await;
        match result {
            Ok(output) => match native_php_fpm_output_plan(php, output, plan) {
                Ok(response)
                    if native_php_response_retryable(php, &response)
                        && attempts < max_retries
                        && fluxheim_php_fpm::php_fpm_retry_deadline_allows(retry_deadline) =>
                {
                    attempts += 1;
                    continue;
                }
                Ok(response) => return Ok(response),
                Err(error)
                    if php.fpm.retry_invalid_response
                        && attempts < max_retries
                        && fluxheim_php_fpm::php_fpm_retry_deadline_allows(retry_deadline) =>
                {
                    attempts += 1;
                    log::debug!(
                        target: "fluxheim::native_http1",
                        "retrying native php-fpm request after invalid response: {error}"
                    );
                }
                Err(error) => return Err(error),
            },
            Err(error)
                if attempts < max_retries
                    && fluxheim_php_fpm::php_fpm_retryable_error(&error)
                    && fluxheim_php_fpm::php_fpm_retry_deadline_allows(retry_deadline) =>
            {
                attempts += 1;
                log::debug!(
                    target: "fluxheim::native_http1",
                    "retrying native php-fpm request after {error}"
                );
            }
            Err(error) => return Err(error),
        }
    }
}

fn native_php_fpm_output_plan(
    php: &PhpConfig,
    output: fastcgi_client::Response,
    plan: &NativePhpRequestPlan,
) -> io::Result<NativePhpResponsePlan> {
    let stdout = output.stdout.unwrap_or_default();
    if let Some(stderr) = output.stderr.as_deref()
        && native_php_stderr_matches_failure_pattern(stderr, php)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "php-fpm stderr matched configured failure pattern",
        ));
    }
    native_php_response_plan(
        &stdout,
        php,
        native_php_request_method(plan).unwrap_or("GET"),
    )
}

fn native_php_fastcgi_params(plan: &NativePhpRequestPlan) -> fastcgi_client::Params<'static> {
    let mut params = fastcgi_client::Params::default();
    for (name, value) in &plan.params {
        params.insert(name.clone().into(), value.clone().into());
    }
    params
}

fn native_php_select_endpoint_index(next_endpoint: &AtomicUsize, endpoint_count: usize) -> usize {
    if endpoint_count <= 1 {
        return 0;
    }
    next_endpoint.fetch_add(1, Ordering::Relaxed) % endpoint_count
}

fn native_php_request_method(plan: &NativePhpRequestPlan) -> Option<&str> {
    plan.params
        .iter()
        .find(|(name, _)| name == "REQUEST_METHOD")
        .map(|(_, value)| value.as_str())
}

fn native_php_response_retryable(php: &PhpConfig, response: &NativePhpResponsePlan) -> bool {
    fluxheim_php_fpm::php_fpm_retryable_status(&php.fpm, response.response.status())
}

fn native_php_stderr_matches_failure_pattern(stderr: &[u8], php: &PhpConfig) -> bool {
    let stderr = String::from_utf8_lossy(stderr);
    php.stderr_failure_patterns
        .iter()
        .any(|pattern| !pattern.is_empty() && stderr.contains(pattern))
}

impl NativePhpRequestPlan {
    #[cfg(test)]
    fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(param, _)| param == name)
            .map(|(_, value)| value.as_str())
    }
}

pub(crate) fn native_php_request_plan(
    request: &NativeHttp1Request,
    php: &PhpConfig,
    root: &Path,
    fpm_root: &Path,
    local_script: &Path,
    vhost_name: &str,
    server_port: &str,
) -> io::Result<NativePhpRequestPlan> {
    let target = http1_request_target(&request.method, &request.target)
        .map_err(|_| invalid_php_request("invalid request target"))?;
    let (request_uri, request_path, query) = native_php_request_target_parts(target)?;
    let script = fluxheim_php_fpm::php_script_name_for_request(
        request_path,
        &php.index,
        php.path_info,
        &php.allowed_extensions,
    )
    .ok_or_else(|| invalid_php_request("invalid PHP script path"))?;
    if fluxheim_php_fpm::php_script_name_denied(&php.deny_path_prefixes, &script.script_name) {
        return Err(invalid_php_request("PHP script path is denied"));
    }

    let document_root = fpm_root
        .to_str()
        .ok_or_else(|| invalid_php_request("PHP fpm_root is not valid UTF-8"))?
        .to_owned();
    let script_filename =
        fluxheim_php_fpm::php_fpm_script_filename(root, fpm_root, local_script)
            .ok_or_else(|| invalid_php_request("PHP script path is outside php.root"))?;
    let path_translated = if script.path_info.is_empty() {
        None
    } else {
        Some(
            fluxheim_php_fpm::php_fpm_path_translated(fpm_root, &script.path_info)
                .ok_or_else(|| invalid_php_request("PHP PATH_INFO cannot be translated"))?,
        )
    };
    let host = native_php_request_host(request)
        .or_else(|| native_php_target_authority(target))
        .unwrap_or(vhost_name);
    let server_name = fluxheim_php_fpm::php_server_name_param(host, vhost_name);
    let (remote_addr, remote_port) = native_php_remote_peer(request);
    let server_addr = request
        .local_addr
        .map(|address| address.ip().to_string())
        .unwrap_or_default();
    let content_type = native_php_content_type_param(request);
    let request_scheme = if request.downstream_tls {
        "https"
    } else {
        "http"
    };

    let mut params = vec![
        ("GATEWAY_INTERFACE".to_owned(), "CGI/1.1".to_owned()),
        ("SERVER_SOFTWARE".to_owned(), "fluxheim".to_owned()),
        (
            "SERVER_PROTOCOL".to_owned(),
            native_php_server_protocol(request.version).to_owned(),
        ),
        ("REQUEST_METHOD".to_owned(), request.method.clone()),
        ("SCRIPT_NAME".to_owned(), script.script_name.clone()),
        ("SCRIPT_FILENAME".to_owned(), script_filename.clone()),
        (
            "QUERY_STRING".to_owned(),
            query.unwrap_or_default().to_owned(),
        ),
        ("REQUEST_URI".to_owned(), request_uri.to_owned()),
        ("DOCUMENT_ROOT".to_owned(), document_root),
        ("DOCUMENT_URI".to_owned(), script.script_name.clone()),
        ("REMOTE_ADDR".to_owned(), remote_addr),
        ("REMOTE_PORT".to_owned(), remote_port),
        ("SERVER_ADDR".to_owned(), server_addr),
        ("SERVER_PORT".to_owned(), server_port.to_owned()),
        ("SERVER_NAME".to_owned(), server_name),
        ("CONTENT_TYPE".to_owned(), content_type),
        ("CONTENT_LENGTH".to_owned(), request.body.len().to_string()),
        ("REQUEST_SCHEME".to_owned(), request_scheme.to_owned()),
        (
            "HTTPS".to_owned(),
            if request.downstream_tls { "on" } else { "off" }.to_owned(),
        ),
        ("REDIRECT_STATUS".to_owned(), "200".to_owned()),
    ];
    if php.pass_request_headers {
        params.extend(fluxheim_php_fpm::php_request_header_params(
            request
                .headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_str())),
        ));
        if let Some((name, value)) = fluxheim_php_fpm::php_host_param(host) {
            params.push((name, value));
        }
    }
    let (accepted, dropped_custom_params) = fluxheim_php_fpm::php_custom_params(
        php.params
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str())),
    );
    params.extend(accepted);
    if !script.path_info.is_empty() {
        params.push(("PATH_INFO".to_owned(), script.path_info.clone()));
        if let Some(path_translated) = &path_translated {
            params.push(("PATH_TRANSLATED".to_owned(), path_translated.clone()));
        }
    }

    Ok(NativePhpRequestPlan {
        script_name: script.script_name,
        path_info: script.path_info,
        script_filename,
        path_translated,
        params,
        dropped_custom_params,
    })
}

fn native_php_request_target_parts(
    target: Http1RequestTarget<'_>,
) -> io::Result<(&str, &str, Option<&str>)> {
    match target {
        Http1RequestTarget::Origin { raw, path, query } => Ok((raw, path, query)),
        Http1RequestTarget::AbsoluteUri {
            raw, path, query, ..
        } => Ok((raw, path.unwrap_or("/"), query)),
        Http1RequestTarget::Authority { .. } | Http1RequestTarget::Asterisk => {
            Err(invalid_php_request("unsupported PHP request target"))
        }
    }
}

fn native_php_target_authority(target: Http1RequestTarget<'_>) -> Option<&str> {
    match target {
        Http1RequestTarget::AbsoluteUri { authority, .. } => authority,
        _ => None,
    }
}

fn native_php_request_host(request: &NativeHttp1Request) -> Option<&str> {
    request.headers.iter().find_map(|(name, value)| {
        name.eq_ignore_ascii_case("host")
            .then_some(value.trim())
            .filter(|value| !value.is_empty())
    })
}

fn native_php_content_type_param(request: &NativeHttp1Request) -> String {
    fluxheim_php_fpm::php_content_type_param_value(
        request
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| value.as_str()),
    )
}

fn native_php_remote_peer(request: &NativeHttp1Request) -> (String, String) {
    request
        .effective_client_addr
        .or(request.peer_addr)
        .map(|address| {
            let ip = match address.ip() {
                IpAddr::V4(address) => IpAddr::V4(address),
                IpAddr::V6(address) => address
                    .to_ipv4_mapped()
                    .map(IpAddr::V4)
                    .unwrap_or(IpAddr::V6(address)),
            };
            (ip.to_string(), address.port().to_string())
        })
        .unwrap_or_else(|| (String::new(), String::new()))
}

fn native_php_server_protocol(version: Http1Version) -> &'static str {
    match version {
        Http1Version::Http10 => "HTTP/1.0",
        Http1Version::Http11 => "HTTP/1.1",
    }
}

fn invalid_php_request(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
#[path = "native_http1_php_tests.rs"]
mod native_http1_php_tests;
