use std::io;
use std::io::Write as _;

use crate::http_types::{
    PingoraRequestHeader as RequestHeader, PingoraResponseHeader as ResponseHeader, StatusCode,
};
#[cfg(feature = "compression-brotli")]
use brotli::CompressorWriter;
use bytes::Bytes;
#[cfg(feature = "compression-gzip")]
use flate2::{Compression, write::GzEncoder};
use pingora::ErrorType;
use pingora::prelude::Result;

use crate::flux_error::FluxError;

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
pub(crate) struct ResponseCompressionEncoder {
    pub(crate) encoding: &'static str,
    inner: ResponseCompressionEncoderInner,
    emitted: usize,
    max_output_bytes: usize,
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
enum ResponseCompressionEncoderInner {
    #[cfg(feature = "compression-brotli")]
    Brotli(Box<Option<CompressorWriter<Vec<u8>>>>),
    #[cfg(feature = "compression-gzip")]
    Gzip(GzEncoder<Vec<u8>>),
    #[cfg(feature = "compression-zstd")]
    Zstd(Option<zstd::stream::write::Encoder<'static, Vec<u8>>>),
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
impl std::fmt::Debug for ResponseCompressionEncoder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResponseCompressionEncoder")
            .field("encoding", &self.encoding)
            .field("emitted", &self.emitted)
            .finish_non_exhaustive()
    }
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
impl ResponseCompressionEncoder {
    #[cfg(feature = "compression-brotli")]
    pub(crate) fn brotli(quality: u32, max_output_bytes: usize) -> Self {
        Self {
            encoding: "br",
            inner: ResponseCompressionEncoderInner::Brotli(Box::new(Some(CompressorWriter::new(
                Vec::new(),
                4096,
                quality,
                22,
            )))),
            emitted: 0,
            max_output_bytes,
        }
    }

    #[cfg(feature = "compression-gzip")]
    pub(crate) fn gzip(level: u32, max_output_bytes: usize) -> Self {
        Self {
            encoding: "gzip",
            inner: ResponseCompressionEncoderInner::Gzip(GzEncoder::new(
                Vec::new(),
                Compression::new(level),
            )),
            emitted: 0,
            max_output_bytes,
        }
    }

    #[cfg(feature = "compression-zstd")]
    pub(crate) fn zstd(level: i32, max_output_bytes: usize) -> io::Result<Self> {
        Ok(Self {
            encoding: "zstd",
            inner: ResponseCompressionEncoderInner::Zstd(Some(zstd::stream::write::Encoder::new(
                Vec::new(),
                level,
            )?)),
            emitted: 0,
            max_output_bytes,
        })
    }

    pub(crate) fn encode_chunk(
        &mut self,
        input: Option<&Bytes>,
        end_of_stream: bool,
    ) -> io::Result<Bytes> {
        match &mut self.inner {
            #[cfg(feature = "compression-brotli")]
            ResponseCompressionEncoderInner::Brotli(encoder_slot) => {
                let Some(mut encoder) = encoder_slot.as_mut().take() else {
                    return Ok(Bytes::new());
                };
                if let Some(input) = input {
                    encoder.write_all(input)?;
                }
                let output = if end_of_stream {
                    encoder.into_inner()
                } else {
                    encoder.flush()?;
                    let bytes = copy_new_compression_bytes(
                        encoder.get_ref(),
                        &mut self.emitted,
                        self.max_output_bytes,
                    )?;
                    *encoder_slot.as_mut() = Some(encoder);
                    return Ok(bytes);
                };
                copy_new_compression_bytes(&output, &mut self.emitted, self.max_output_bytes)
            }
            #[cfg(feature = "compression-gzip")]
            ResponseCompressionEncoderInner::Gzip(encoder) => {
                if let Some(input) = input {
                    encoder.write_all(input)?;
                }
                if end_of_stream {
                    encoder.try_finish()?;
                } else {
                    encoder.flush()?;
                }
                copy_new_compression_bytes(
                    encoder.get_ref(),
                    &mut self.emitted,
                    self.max_output_bytes,
                )
            }
            #[cfg(feature = "compression-zstd")]
            ResponseCompressionEncoderInner::Zstd(encoder_slot) => {
                let Some(mut encoder) = encoder_slot.take() else {
                    return Ok(Bytes::new());
                };
                if let Some(input) = input {
                    encoder.write_all(input)?;
                }
                let output = if end_of_stream {
                    encoder.finish()?
                } else {
                    encoder.flush()?;
                    let bytes = copy_new_compression_bytes(
                        encoder.get_ref(),
                        &mut self.emitted,
                        self.max_output_bytes,
                    )?;
                    *encoder_slot = Some(encoder);
                    return Ok(bytes);
                };
                copy_new_compression_bytes(&output, &mut self.emitted, self.max_output_bytes)
            }
        }
    }
}

#[cfg(any(
    feature = "compression-brotli",
    feature = "compression-gzip",
    feature = "compression-zstd"
))]
fn copy_new_compression_bytes(
    output: &[u8],
    emitted: &mut usize,
    max_output_bytes: usize,
) -> io::Result<Bytes> {
    if output.len() > max_output_bytes {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "compressed response exceeds max_output_bytes",
        ));
    }
    let bytes = Bytes::copy_from_slice(&output[*emitted..]);
    *emitted = output.len();
    Ok(bytes)
}

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
        FluxError::io("response compression initialization failed", error)
            .into_pingora(ErrorType::InternalError)
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
    ) -> io::Result<ResponseCompressionEncoder> {
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
fn encoding_token_allows(token: &str, expected: &str) -> bool {
    let mut parts = token.split(';');
    let coding = parts.next().unwrap_or_default().trim();
    if !coding.eq_ignore_ascii_case(expected) && coding != "*" {
        return false;
    }

    !parts
        .map(str::trim)
        .filter_map(|parameter| parameter.split_once('='))
        .any(|(name, value)| {
            name.trim().eq_ignore_ascii_case("q")
                && value
                    .trim()
                    .parse::<f32>()
                    .is_ok_and(|quality| quality <= 0.0)
        })
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
        .any(|value| !value.trim().eq_ignore_ascii_case("identity"))
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
        .any(|directive| {
            directive.eq_ignore_ascii_case("no-transform")
                || directive.eq_ignore_ascii_case("private")
                || directive.eq_ignore_ascii_case("no-store")
        })
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
        .map(|value| {
            value
                .split(';')
                .next()
                .unwrap_or_default()
                .trim()
                .to_ascii_lowercase()
        })
    else {
        return false;
    };

    content_type.as_str().starts_with("text/")
        || matches!(
            content_type.as_str(),
            "application/javascript"
                | "application/json"
                | "application/xml"
                | "image/svg+xml"
                | "text/javascript"
        )
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
    length >= config.min_bytes.as_u64() && length <= config.max_input_bytes.as_u64()
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
