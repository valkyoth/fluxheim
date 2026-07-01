use fluxheim_config::GrpcRouteConfig;

use crate::{NativeHttp1Request, NativeHttp1Response};

pub(crate) fn native_grpc_rejection_response(
    grpc: &GrpcRouteConfig,
    request: &NativeHttp1Request,
) -> Option<NativeHttp1Response> {
    if !grpc.enabled {
        return None;
    }
    if request.method != "POST" {
        return Some(
            NativeHttp1Response::new(405, "Method Not Allowed", b"method not allowed\n")
                .with_header("Allow", "POST")
                .with_header("grpc-status", "12")
                .with_header("grpc-message", "method not allowed; gRPC requires POST")
                .close_connection(),
        );
    }
    if grpc.require_content_type {
        let mut content_types = native_request_header_values(request, "content-type");
        let Some(content_type) = content_types.next() else {
            return Some(native_grpc_unsupported_media_type_response());
        };
        if content_types.next().is_some() || !native_grpc_content_type(content_type) {
            return Some(native_grpc_unsupported_media_type_response());
        }
    }
    None
}

fn native_grpc_unsupported_media_type_response() -> NativeHttp1Response {
    NativeHttp1Response::new(415, "Unsupported Media Type", b"unsupported media type\n")
        .with_header("grpc-status", "3")
        .with_header("grpc-message", "content-type must be application/grpc")
        .close_connection()
}

fn native_grpc_content_type(value: &str) -> bool {
    let media_type = value
        .split_once(';')
        .map(|(media_type, _)| media_type)
        .unwrap_or(value)
        .trim();
    media_type.eq_ignore_ascii_case("application/grpc")
        || media_type
            .get(.."application/grpc+".len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case("application/grpc+"))
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
