use crate::http_types::{
    PingoraRequestHeader as RequestHeader, PingoraResponseHeader as ResponseHeader, StatusCode,
};
use pingora::ErrorType;
use pingora::prelude::Result;

use crate::flux_error::{FluxErrorPingoraExt, FluxResult};

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
pub(crate) use fluxheim_compression::ResponseCompressionEncoder;
#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
use fluxheim_compression::{
    cache_control_directive_blocks_compression, content_encoding_value_is_active,
    content_type_is_compressible, encoding_token_allows, input_length_within_compression_bounds,
};

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
pub(crate) fn prepare_response_compression(
    request: &RequestHeader,
    response: &mut ResponseHeader,
    config: &crate::config::CompressionConfig,
) -> Result<Option<ResponseCompressionEncoder>> {
    let Some(encoding) = selected_response_compression(request, response, config) else {
        return Ok(None);
    };

    response.insert_header("content-encoding", encoding.content_encoding())?;
    response.remove_header("content-length");
    response.remove_header("etag");
    append_vary_accept_encoding(response)?;
    Ok(Some(encoding.encoder(config).map_err(|error| {
        error.into_pingora(ErrorType::InternalError)
    })?))
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ResponseCompressionEncoding {
    #[cfg(feature = "compression-brotli")]
    Brotli,
    #[cfg(feature = "compression-gzip")]
    Gzip,
    #[cfg(feature = "compression-zstd")]
    Zstd,
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
impl ResponseCompressionEncoding {
    fn content_encoding(self) -> &'static str {
        match self {
            #[cfg(feature = "compression-brotli")]
            Self::Brotli => "br",
            #[cfg(feature = "compression-gzip")]
            Self::Gzip => "gzip",
            #[cfg(feature = "compression-zstd")]
            Self::Zstd => "zstd",
        }
    }

    fn encoder(
        self,
        config: &crate::config::CompressionConfig,
    ) -> FluxResult<ResponseCompressionEncoder> {
        match self {
            #[cfg(feature = "compression-brotli")]
            Self::Brotli => Ok(ResponseCompressionEncoder::brotli(
                config.brotli_quality,
                compression_max_output_bytes(config),
            )),
            #[cfg(feature = "compression-gzip")]
            Self::Gzip => Ok(ResponseCompressionEncoder::gzip(
                config.gzip_level,
                compression_max_output_bytes(config),
            )),
            #[cfg(feature = "compression-zstd")]
            Self::Zstd => ResponseCompressionEncoder::zstd(
                config.zstd_level,
                compression_max_output_bytes(config),
            ),
        }
    }
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn compression_max_output_bytes(config: &crate::config::CompressionConfig) -> usize {
    usize::try_from(config.max_output_bytes.as_u64()).unwrap_or(usize::MAX)
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
pub(crate) fn selected_response_compression(
    request: &RequestHeader,
    response: &ResponseHeader,
    config: &crate::config::CompressionConfig,
) -> Option<ResponseCompressionEncoding> {
    if !(config.enabled
        && request.method.as_str() == "GET"
        && response.status == StatusCode::OK
        && !response_has_content_encoding(response)
        && !response.headers.contains_key("content-range")
        && !response.headers.contains_key("set-cookie")
        && !request.headers.contains_key("authorization")
        && !request.headers.contains_key("cookie")
        && !response_cache_control_blocks_compression(response)
        && response_content_type_is_compressible(response)
        && response_content_length_in_compression_bounds(response, config))
    {
        return None;
    }

    #[cfg(feature = "compression-brotli")]
    if config.brotli && request_accepts_encoding(request, "br") {
        return Some(ResponseCompressionEncoding::Brotli);
    }
    #[cfg(feature = "compression-zstd")]
    if config.zstd && request_accepts_encoding(request, "zstd") {
        return Some(ResponseCompressionEncoding::Zstd);
    }
    #[cfg(feature = "compression-gzip")]
    if config.gzip && request_accepts_encoding(request, "gzip") {
        return Some(ResponseCompressionEncoding::Gzip);
    }

    None
}

#[cfg(all(test, feature = "compression-gzip"))]
pub(crate) fn gzip_response_eligible(
    request: &RequestHeader,
    response: &ResponseHeader,
    config: &crate::config::CompressionConfig,
) -> bool {
    selected_response_compression(request, response, config)
        == Some(ResponseCompressionEncoding::Gzip)
}

#[cfg(all(test, feature = "compression-gzip"))]
pub(crate) fn request_accepts_gzip(request: &RequestHeader) -> bool {
    request_accepts_encoding(request, "gzip")
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn request_accepts_encoding(request: &RequestHeader, expected: &str) -> bool {
    request
        .headers
        .get_all("accept-encoding")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|token| encoding_token_allows(token, expected))
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn response_has_content_encoding(response: &ResponseHeader) -> bool {
    response
        .headers
        .get_all("content-encoding")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .any(content_encoding_value_is_active)
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn response_cache_control_blocks_compression(response: &ResponseHeader) -> bool {
    response
        .headers
        .get_all("cache-control")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .any(cache_control_directive_blocks_compression)
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn response_content_type_is_compressible(response: &ResponseHeader) -> bool {
    let Some(content_type) = response
        .headers
        .get("content-type")
        .and_then(|value| value.to_str().ok())
    else {
        return false;
    };

    content_type_is_compressible(content_type)
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn response_content_length_in_compression_bounds(
    response: &ResponseHeader,
    config: &crate::config::CompressionConfig,
) -> bool {
    let Some(length) = response
        .headers
        .get("content-length")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.parse::<u64>().ok())
    else {
        return false;
    };
    input_length_within_compression_bounds(
        length,
        config.min_bytes.as_u64(),
        config.max_input_bytes.as_u64(),
    )
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn append_vary_accept_encoding(response: &mut ResponseHeader) -> Result<()> {
    let has_accept_encoding = response
        .headers
        .get_all("vary")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .any(|field| field.trim().eq_ignore_ascii_case("accept-encoding"));
    if !has_accept_encoding {
        response.append_header("vary", "accept-encoding")?;
    }
    Ok(())
}
