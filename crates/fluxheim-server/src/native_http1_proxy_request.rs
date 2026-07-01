use std::time::Duration;

use crate::{NativeHttp1Request, NativeHttp1ResponseWritePolicy};

pub(crate) fn native_response_write_policy_from_config(
    proxy: &fluxheim_config::ProxyConfig,
) -> NativeHttp1ResponseWritePolicy {
    NativeHttp1ResponseWritePolicy::new(
        proxy.downstream_write_timeout_secs.map(Duration::from_secs),
        proxy
            .downstream_total_response_timeout_secs
            .map(Duration::from_secs),
        proxy.downstream_min_send_rate_bytes_per_sec,
    )
}

pub(crate) fn native_request_is_websocket_upgrade(request: &NativeHttp1Request) -> bool {
    request.method == "GET"
        && native_request_header_values(request, "upgrade")
            .any(|value| value.trim().eq_ignore_ascii_case("websocket"))
        && native_request_header_values(request, "connection").any(|value| {
            value
                .split(',')
                .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
        })
        && native_request_header_values(request, "sec-websocket-key").count() == 1
        && native_request_header_values(request, "sec-websocket-version")
            .any(|value| value.trim() == "13")
}

pub(crate) fn native_request_header_values<'a>(
    request: &'a NativeHttp1Request,
    name: &'a str,
) -> impl Iterator<Item = &'a str> {
    request
        .headers
        .iter()
        .filter(move |(header_name, _)| header_name.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

pub(crate) fn native_request_header<'a>(
    request: &'a NativeHttp1Request,
    name: &str,
) -> Option<&'a str> {
    request
        .headers
        .iter()
        .find_map(|(header_name, value)| header_name.eq_ignore_ascii_case(name).then_some(value))
        .map(String::as_str)
}

pub(crate) fn native_proxy_error_is_timeout(error: &crate::NativeHttp1Error) -> bool {
    matches!(
        error,
        crate::NativeHttp1Error::Io(error) if error.kind() == std::io::ErrorKind::TimedOut
    )
}
