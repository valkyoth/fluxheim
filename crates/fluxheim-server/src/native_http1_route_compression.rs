use fluxheim_compression::{
    ResponseCompressionEncoder, accept_encoding_quality,
    cache_control_directive_blocks_compression, content_encoding_value_is_active,
    content_type_is_compressible, input_length_within_compression_bounds,
};

use crate::{NativeHttp1Request, NativeHttp1Response};

pub(crate) fn apply_route_compression(
    request: &NativeHttp1Request,
    response: &mut NativeHttp1Response,
    config: &fluxheim_config::CompressionConfig,
) {
    apply_native_response_compression(request, response, config);
}

pub(crate) fn apply_native_response_compression(
    request: &NativeHttp1Request,
    response: &mut NativeHttp1Response,
    config: &fluxheim_config::CompressionConfig,
) {
    let Some(mut encoder) = selected_route_compression(request, response, config) else {
        return;
    };
    match encoder.encode_chunk(Some(response.body()), true) {
        Ok(encoded) => {
            response.remove_header("content-encoding");
            response.remove_header("content-length");
            response.remove_header("etag");
            response.push_header("content-encoding", encoder.encoding);
            append_vary_accept_encoding(response);
            response.replace_body(encoded);
        }
        Err(error) => {
            log::debug!(
                target: "fluxheim::native",
                "native route response compression skipped: {error}"
            );
        }
    }
}

fn selected_route_compression(
    request: &NativeHttp1Request,
    response: &NativeHttp1Response,
    config: &fluxheim_config::CompressionConfig,
) -> Option<ResponseCompressionEncoder> {
    if !(config.enabled
        && request.method == "GET"
        && response.status() == 200
        && !response_has_content_encoding(response)
        && !response_has_header(response, "content-range")
        && !response_has_header(response, "set-cookie")
        && !request_has_header(request, "authorization")
        && !request_has_header(request, "cookie")
        && !response_cache_control_blocks_compression(response)
        && response_content_type_is_compressible(response)
        && response_content_length_in_compression_bounds(response, config))
    {
        return None;
    }

    let mut candidates = Vec::new();
    #[cfg(feature = "compression-brotli")]
    if config.brotli
        && let Some(quality) = request_accept_encoding_quality(request, "br")
    {
        candidates.push((quality, 0u8, "br"));
    }
    #[cfg(feature = "compression-zstd")]
    if config.zstd
        && let Some(quality) = request_accept_encoding_quality(request, "zstd")
    {
        candidates.push((quality, 1u8, "zstd"));
    }
    #[cfg(feature = "compression-gzip")]
    if config.gzip
        && let Some(quality) = request_accept_encoding_quality(request, "gzip")
    {
        candidates.push((quality, 2u8, "gzip"));
    }
    candidates.sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));

    for (_, _, encoding) in candidates {
        if let Some(encoder) = route_compression_encoder(encoding, config) {
            return Some(encoder);
        }
    }

    None
}

fn route_compression_encoder(
    encoding: &str,
    config: &fluxheim_config::CompressionConfig,
) -> Option<ResponseCompressionEncoder> {
    match encoding {
        #[cfg(feature = "compression-brotli")]
        "br" => Some(ResponseCompressionEncoder::brotli(
            config.brotli_quality,
            compression_max_output_bytes(config),
        )),
        #[cfg(feature = "compression-zstd")]
        "zstd" => ResponseCompressionEncoder::zstd(
            config.zstd_level,
            compression_max_output_bytes(config),
        )
        .ok(),
        #[cfg(feature = "compression-gzip")]
        "gzip" => Some(ResponseCompressionEncoder::gzip(
            config.gzip_level,
            compression_max_output_bytes(config),
        )),
        _ => None,
    }
}

fn compression_max_output_bytes(config: &fluxheim_config::CompressionConfig) -> usize {
    usize::try_from(config.max_output_bytes.as_u64()).unwrap_or(usize::MAX)
}

fn request_accept_encoding_quality(request: &NativeHttp1Request, expected: &str) -> Option<u16> {
    accept_encoding_quality(
        request
            .headers
            .iter()
            .filter(|(name, _)| name.eq_ignore_ascii_case("accept-encoding"))
            .map(|(_, value)| value.as_str()),
        expected,
    )
}

fn response_has_content_encoding(response: &NativeHttp1Response) -> bool {
    response
        .headers()
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("content-encoding"))
        .any(|(_, value)| content_encoding_value_is_active(value))
}

fn request_has_header(request: &NativeHttp1Request, name: &str) -> bool {
    request
        .headers
        .iter()
        .any(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
}

fn response_has_header(response: &NativeHttp1Response, name: &str) -> bool {
    response
        .headers()
        .iter()
        .any(|(header_name, _)| header_name.eq_ignore_ascii_case(name))
}

fn response_cache_control_blocks_compression(response: &NativeHttp1Response) -> bool {
    response
        .headers()
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("cache-control"))
        .flat_map(|(_, value)| value.split(','))
        .map(str::trim)
        .any(cache_control_directive_blocks_compression)
}

fn response_content_type_is_compressible(response: &NativeHttp1Response) -> bool {
    response
        .headers()
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
        .is_some_and(|(_, value)| content_type_is_compressible(value))
}

fn response_content_length_in_compression_bounds(
    response: &NativeHttp1Response,
    config: &fluxheim_config::CompressionConfig,
) -> bool {
    let length = response
        .content_length()
        .unwrap_or_else(|| response.body().len() as u64);
    input_length_within_compression_bounds(
        length,
        config.min_bytes.as_u64(),
        config.max_input_bytes.as_u64(),
    )
}

fn append_vary_accept_encoding(response: &mut NativeHttp1Response) {
    let has_accept_encoding = response
        .headers()
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("vary"))
        .flat_map(|(_, value)| value.split(','))
        .any(|field| field.trim().eq_ignore_ascii_case("accept-encoding"));
    if !has_accept_encoding {
        response.push_header("vary", "accept-encoding");
    }
}
