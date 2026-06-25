#![allow(
    dead_code,
    reason = "native PHP-FPM request planning is staged before route runtime wiring"
)]

use std::io;
use std::net::IpAddr;
use std::path::Path;

use fluxheim_config::PhpConfig;
use fluxheim_protocol::{Http1RequestTarget, Http1Version, http1_request_target};

use crate::{NativeHttp1Request, NativeHttp1Response};

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

impl NativePhpRequestPlan {
    #[cfg(test)]
    fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(param, _)| param == name)
            .map(|(_, value)| value.as_str())
    }
}

pub(crate) fn native_php_response_plan(
    stdout: &[u8],
    php: &PhpConfig,
    request_method: &str,
) -> io::Result<NativePhpResponsePlan> {
    let parsed = fluxheim_php_fpm::parse_php_response(
        stdout,
        php.max_response_bytes.as_u64(),
        php.max_response_header_bytes.as_u64(),
    )?;
    let connection_values = parsed
        .headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("connection"))
        .map(|(_, value)| value.as_str());
    let headers_to_strip = fluxheim_php_fpm::php_response_headers_to_strip(
        connection_values,
        &php.hide_response_headers,
    );
    let body_len = parsed.body.len() as u64;
    let body = if request_method.eq_ignore_ascii_case("HEAD") {
        Vec::new()
    } else {
        parsed.body
    };
    let mut response =
        NativeHttp1Response::new(parsed.status, native_php_status_reason(parsed.status), body)
            .with_content_length(body_len);
    for (name, value) in parsed.headers {
        if native_php_response_header_stripped(&name, &headers_to_strip) {
            continue;
        }
        response.push_header(name, value);
    }
    if php.ignore_origin_cache_headers {
        response.remove_header("cache-control");
        response.remove_header("expires");
        response.remove_header("pragma");
    }

    let intercept_status = fluxheim_php_fpm::php_should_intercept_error_status(
        parsed.status,
        php.error_pages.iter().map(|page| page.status),
        &php.intercept_error_statuses,
    )
    .then_some(parsed.status);
    Ok(NativePhpResponsePlan {
        response,
        intercept_status,
    })
}

fn native_php_response_header_stripped(name: &str, headers_to_strip: &[String]) -> bool {
    name.eq_ignore_ascii_case("content-length")
        || name.eq_ignore_ascii_case("x-accel-expires")
        || fluxheim_php_fpm::PHP_STATIC_OFFLOAD_RESPONSE_HEADERS
            .iter()
            .any(|internal| name.eq_ignore_ascii_case(internal))
        || headers_to_strip
            .iter()
            .any(|header| name.eq_ignore_ascii_case(header))
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

fn native_php_status_reason(status: u16) -> &'static str {
    match status {
        100 => "Continue",
        101 => "Switching Protocols",
        200 => "OK",
        201 => "Created",
        202 => "Accepted",
        204 => "No Content",
        206 => "Partial Content",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        410 => "Gone",
        412 => "Precondition Failed",
        413 => "Payload Too Large",
        416 => "Range Not Satisfiable",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "",
    }
}

fn invalid_php_request(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::net::SocketAddr;
    use std::path::Path;

    use fluxheim_protocol::Http1Version;

    use super::{NativeHttp1Request, native_php_request_plan, native_php_response_plan};

    fn request(target: &str) -> NativeHttp1Request {
        NativeHttp1Request {
            method: "POST".to_owned(),
            peer_addr: Some(SocketAddr::from(([192, 0, 2, 10], 43123))),
            local_addr: Some(SocketAddr::from(([127, 0, 0, 1], 8443))),
            effective_client_addr: Some(SocketAddr::from(([203, 0, 113, 7], 52444))),
            downstream_tls: true,
            tls_identity: None,
            geo_context: None,
            target: target.to_owned(),
            version: Http1Version::Http11,
            headers: vec![
                ("host".to_owned(), "app.example".to_owned()),
                (
                    "content-type".to_owned(),
                    "application/x-www-form-urlencoded".to_owned(),
                ),
                ("cookie".to_owned(), "a=1".to_owned()),
                ("cookie".to_owned(), "b=2".to_owned()),
                ("x-test".to_owned(), "one".to_owned()),
                ("x-test".to_owned(), "two".to_owned()),
                ("proxy".to_owned(), "drop-me".to_owned()),
            ],
            body: b"name=fluxheim".to_vec(),
        }
    }

    fn php_config() -> fluxheim_config::PhpConfig {
        fluxheim_config::PhpConfig {
            enabled: true,
            path_info: fluxheim_config::PhpPathInfoMode::Split,
            params: BTreeMap::from([
                ("APP_ENV".to_owned(), "test".to_owned()),
                ("SCRIPT_FILENAME".to_owned(), "/tmp/bypass.php".to_owned()),
            ]),
            ..Default::default()
        }
    }

    #[test]
    fn native_php_request_plan_maps_core_fastcgi_params() {
        let plan = native_php_request_plan(
            &request("/index.php/user?id=1"),
            &php_config(),
            Path::new("/srv/www"),
            Path::new("/var/www/html"),
            Path::new("/srv/www/index.php"),
            "fallback.example",
            "443",
        )
        .unwrap();

        assert_eq!(plan.script_name, "/index.php");
        assert_eq!(plan.path_info, "/user");
        assert_eq!(plan.script_filename, "/var/www/html/index.php");
        assert_eq!(plan.path_translated.as_deref(), Some("/var/www/html/user"));
        assert_eq!(plan.param("REQUEST_METHOD"), Some("POST"));
        assert_eq!(plan.param("SERVER_PROTOCOL"), Some("HTTP/1.1"));
        assert_eq!(plan.param("QUERY_STRING"), Some("id=1"));
        assert_eq!(plan.param("REQUEST_URI"), Some("/index.php/user?id=1"));
        assert_eq!(plan.param("REMOTE_ADDR"), Some("203.0.113.7"));
        assert_eq!(plan.param("REMOTE_PORT"), Some("52444"));
        assert_eq!(plan.param("SERVER_ADDR"), Some("127.0.0.1"));
        assert_eq!(plan.param("SERVER_PORT"), Some("443"));
        assert_eq!(plan.param("SERVER_NAME"), Some("app.example"));
        assert_eq!(plan.param("CONTENT_LENGTH"), Some("13"));
        assert_eq!(
            plan.param("CONTENT_TYPE"),
            Some("application/x-www-form-urlencoded")
        );
        assert_eq!(plan.param("REQUEST_SCHEME"), Some("https"));
        assert_eq!(plan.param("HTTPS"), Some("on"));
        assert_eq!(plan.param("HTTP_COOKIE"), Some("a=1; b=2"));
        assert_eq!(plan.param("HTTP_X_TEST"), Some("one, two"));
        assert_eq!(plan.param("HTTP_PROXY"), None);
        assert_eq!(plan.param("APP_ENV"), Some("test"));
        assert_eq!(
            plan.param("SCRIPT_FILENAME"),
            Some("/var/www/html/index.php")
        );
        assert_eq!(plan.dropped_custom_params, vec!["SCRIPT_FILENAME"]);
    }

    #[test]
    fn native_php_request_plan_rejects_denied_scripts() {
        let php = fluxheim_config::PhpConfig {
            enabled: true,
            deny_path_prefixes: vec!["/admin".to_owned()],
            ..Default::default()
        };
        let error = native_php_request_plan(
            &request("/admin/index.php"),
            &php,
            Path::new("/srv/www"),
            Path::new("/var/www/html"),
            Path::new("/srv/www/admin/index.php"),
            "fallback.example",
            "443",
        )
        .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn native_php_request_plan_rejects_unsafe_path_info() {
        let php = fluxheim_config::PhpConfig {
            enabled: true,
            path_info: fluxheim_config::PhpPathInfoMode::Split,
            ..Default::default()
        };
        let error = native_php_request_plan(
            &request("/index.php/%2e%2e/secret"),
            &php,
            Path::new("/srv/www"),
            Path::new("/var/www/html"),
            Path::new("/srv/www/index.php"),
            "fallback.example",
            "443",
        )
        .unwrap_err();

        assert_eq!(error.kind(), std::io::ErrorKind::InvalidInput);
    }

    #[test]
    fn native_php_response_plan_strips_owned_and_hidden_headers() {
        let php = fluxheim_config::PhpConfig {
            enabled: true,
            hide_response_headers: vec!["x-powered-by".to_owned()],
            ..Default::default()
        };
        let plan = native_php_response_plan(
            b"Status: 201 Created\r\n\
              Content-Type: text/plain\r\n\
              Content-Length: 999\r\n\
              Connection: x-internal\r\n\
              X-Internal: secret\r\n\
              X-Powered-By: php\r\n\
              X-Accel-Redirect: /private\r\n\
              X-Sendfile: /private/file\r\n\
              X-Accel-Expires: 60\r\n\
              \r\n\
              hello",
            &php,
            "GET",
        )
        .unwrap();

        assert_eq!(plan.intercept_status, None);
        assert_eq!(plan.response.status(), 201);
        assert_eq!(plan.response.content_length(), Some(5));
        assert_eq!(plan.response.body(), b"hello");
        assert!(plan.response.headers().iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("content-type") && value == "text/plain"
        }));
        for stripped in [
            "content-length",
            "connection",
            "x-internal",
            "x-powered-by",
            "x-accel-redirect",
            "x-sendfile",
            "x-accel-expires",
        ] {
            assert!(
                !plan
                    .response
                    .headers()
                    .iter()
                    .any(|(name, _)| name.eq_ignore_ascii_case(stripped)),
                "{stripped} should be stripped"
            );
        }
    }

    #[test]
    fn native_php_response_plan_keeps_head_length_without_body() {
        let plan = native_php_response_plan(
            b"Content-Type: text/plain\r\n\r\nhello",
            &fluxheim_config::PhpConfig {
                enabled: true,
                ..Default::default()
            },
            "HEAD",
        )
        .unwrap();

        assert_eq!(plan.response.status(), 200);
        assert_eq!(plan.response.content_length(), Some(5));
        assert!(plan.response.body().is_empty());
    }

    #[test]
    fn native_php_response_plan_marks_intercepted_statuses() {
        let php = fluxheim_config::PhpConfig {
            enabled: true,
            intercept_error_statuses: vec![404],
            ..Default::default()
        };
        let plan =
            native_php_response_plan(b"Status: 404 Not Found\r\n\r\nmissing", &php, "GET").unwrap();

        assert_eq!(plan.intercept_status, Some(404));
        assert_eq!(plan.response.status(), 404);
    }
}
