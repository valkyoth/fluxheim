use http::{HeaderMap, StatusCode, header};

use serde::Serialize;

use serde_json::json;

use super::{AdminResponse, MAX_ADMIN_ERROR_MESSAGE_CHARS, MAX_ADMIN_JSON_RESPONSE_BYTES};

pub(super) fn admin_native_http1_response(
    response: AdminResponse,
) -> fluxheim_server::NativeHttp1Response {
    fluxheim_server::NativeHttp1Response::new(
        response.status.as_u16(),
        response
            .status
            .canonical_reason()
            .unwrap_or("Admin Response"),
        response.body,
    )
    .with_header(header::CONTENT_TYPE.as_str(), response.content_type)
    .with_header(header::CACHE_CONTROL.as_str(), "no-store")
}

pub(super) fn native_admin_headers(headers: &[(String, String)]) -> HeaderMap {
    let mut map = HeaderMap::new();
    for (name, value) in headers {
        let Ok(name) = http::HeaderName::try_from(name.as_str()) else {
            continue;
        };
        let Ok(value) = http::HeaderValue::try_from(value.as_str()) else {
            continue;
        };
        map.append(name, value);
    }
    map
}

/// Return `(path, query)` from the raw HTTP request target without
/// percent-decoding. Admin routes must match encoded path strings so a future
/// normalization change cannot introduce a route-bypass gap.
pub(super) fn native_admin_target_parts(target: &str) -> (&str, Option<&str>) {
    let target = match target.split_once('#') {
        Some((before_fragment, _)) => before_fragment,
        None => target,
    };
    if let Some(rest) = target.strip_prefix("http://") {
        native_admin_absolute_target_parts(rest)
    } else if let Some(rest) = target.strip_prefix("https://") {
        native_admin_absolute_target_parts(rest)
    } else {
        native_admin_origin_target_parts(target)
    }
}

pub(super) fn native_admin_absolute_target_parts(
    target_after_scheme: &str,
) -> (&str, Option<&str>) {
    let path_index = target_after_scheme.find('/');
    let query_index = target_after_scheme.find('?');
    match (path_index, query_index) {
        (Some(path_index), Some(query_index)) if query_index < path_index => {
            ("/", nonempty_query(&target_after_scheme[query_index + 1..]))
        }
        (Some(path_index), _) => {
            native_admin_origin_target_parts(&target_after_scheme[path_index..])
        }
        (None, Some(query_index)) => ("/", nonempty_query(&target_after_scheme[query_index + 1..])),
        (None, None) => ("/", None),
    }
}

pub(super) fn native_admin_origin_target_parts(target: &str) -> (&str, Option<&str>) {
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    (path, (!query.is_empty()).then_some(query))
}

pub(super) fn nonempty_query(query: &str) -> Option<&str> {
    (!query.is_empty()).then_some(query)
}

pub(super) fn json_response(status: StatusCode, body: &[u8]) -> AdminResponse {
    if body.len() > MAX_ADMIN_JSON_RESPONSE_BYTES {
        return AdminResponse {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            content_type: "application/json",
            body: br#"{"status":"error","error":"admin JSON response exceeded configured safety limit"}"#
                .to_vec(),
        };
    }

    AdminResponse {
        status,
        content_type: "application/json",
        body: body.to_vec(),
    }
}

pub(super) fn json_response_value(status: StatusCode, body: &impl Serialize) -> AdminResponse {
    match serde_json::to_vec(body) {
        Ok(body) => json_response(status, &body),
        Err(error) => internal_error_response(&error),
    }
}

pub(super) fn empty_response(status: StatusCode) -> AdminResponse {
    AdminResponse {
        status,
        content_type: "application/octet-stream",
        body: Vec::new(),
    }
}

pub(super) fn error_response(status: StatusCode, error: &str) -> AdminResponse {
    let error = bounded_admin_error_message(error);
    json_response_value(status, &json!({"status": "error", "error": error}))
}

pub(super) fn internal_error_response(error: &impl std::fmt::Display) -> AdminResponse {
    log::error!("admin internal error: {error}");
    json_response(
        StatusCode::INTERNAL_SERVER_ERROR,
        br#"{"status":"error","error":"internal_error"}"#,
    )
}

pub(super) fn bounded_admin_error_message(error: &str) -> String {
    let mut bounded: String = error.chars().take(MAX_ADMIN_ERROR_MESSAGE_CHARS).collect();
    if error.chars().count() > MAX_ADMIN_ERROR_MESSAGE_CHARS {
        bounded.push_str("...");
    }
    bounded
}
