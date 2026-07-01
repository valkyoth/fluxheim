use std::io;

use fluxheim_config::PhpConfig;

use crate::NativeHttp1Response;

use super::NativePhpResponsePlan;

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
