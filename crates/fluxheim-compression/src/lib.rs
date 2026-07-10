#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

#[cfg(any(feature = "brotli", feature = "gzip", feature = "zstd"))]
use std::io::Write as _;

#[cfg(feature = "brotli")]
use brotli::CompressorWriter;
#[cfg(any(feature = "brotli", feature = "gzip", feature = "zstd"))]
use bytes::Bytes;
#[cfg(feature = "gzip")]
use flate2::{Compression, write::GzEncoder};
#[cfg(any(feature = "brotli", feature = "gzip", feature = "zstd"))]
use fluxheim_common::{FluxError, FluxResult};

#[cfg(any(feature = "brotli", feature = "gzip", feature = "zstd"))]
mod limited_output;
#[cfg(any(feature = "brotli", feature = "gzip", feature = "zstd"))]
use limited_output::LimitedOutput;

#[cfg(any(feature = "brotli", feature = "gzip", feature = "zstd"))]
pub struct ResponseCompressionEncoder {
    pub encoding: &'static str,
    inner: ResponseCompressionEncoderInner,
    total_output_bytes: usize,
}

pub fn accept_encoding_quality<'a>(
    header_values: impl IntoIterator<Item = &'a str>,
    expected: &str,
) -> Option<u16> {
    let mut specific = None;
    let mut wildcard = None;

    for header in header_values {
        for item in header.split(',') {
            let (coding, quality) = parse_accept_encoding_item(item)?;
            if coding.eq_ignore_ascii_case(expected) {
                specific = Some(specific.map_or(quality, |current: u16| current.min(quality)));
            } else if coding == "*" {
                wildcard = Some(wildcard.map_or(quality, |current: u16| current.min(quality)));
            }
        }
    }

    specific.or(wildcard).filter(|quality| *quality > 0)
}

pub fn accept_encoding_allows(header: &str, expected: &str) -> bool {
    accept_encoding_quality(std::iter::once(header), expected).is_some()
}

fn parse_accept_encoding_item(item: &str) -> Option<(&str, u16)> {
    let mut parts = item.split(';');
    let coding = parts.next()?.trim();
    if coding.is_empty() || !fluxheim_protocol::http_token_valid(coding) {
        return None;
    }

    let mut quality = 1000u16;
    let mut saw_quality = false;
    for parameter in parts {
        let (name, value) = parameter.trim().split_once('=')?;
        if saw_quality || !name.trim().eq_ignore_ascii_case("q") {
            return None;
        }
        quality = parse_accept_encoding_qvalue(value.trim())?;
        saw_quality = true;
    }
    Some((coding, quality))
}

pub fn parse_accept_encoding_qvalue(value: &str) -> Option<u16> {
    let (whole, fraction) = value.split_once('.').unwrap_or((value, ""));
    match whole {
        "0" => {
            if fraction.len() > 3 || !fraction.bytes().all(|byte| byte.is_ascii_digit()) {
                return None;
            }
            let mut per_mille = 0u16;
            let mut scale = 100u16;
            for byte in fraction.bytes() {
                per_mille = per_mille.saturating_add(u16::from(byte - b'0') * scale);
                scale /= 10;
            }
            Some(per_mille)
        }
        "1" => {
            if fraction.len() > 3 || !fraction.bytes().all(|byte| byte == b'0') {
                return None;
            }
            Some(1000)
        }
        _ => None,
    }
}

pub fn cache_control_directive_blocks_compression(directive: &str) -> bool {
    let name = directive
        .split_once('=')
        .map_or(directive, |(name, _)| name)
        .trim();
    name.eq_ignore_ascii_case("no-transform")
        || name.eq_ignore_ascii_case("private")
        || name.eq_ignore_ascii_case("no-store")
}

pub fn content_type_is_compressible(content_type: &str) -> bool {
    let content_type = content_type
        .split(';')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();

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

pub fn content_encoding_value_is_active(value: &str) -> bool {
    !value.trim().eq_ignore_ascii_case("identity")
}

pub fn input_length_within_compression_bounds(length: u64, min_bytes: u64, max_bytes: u64) -> bool {
    length >= min_bytes && length <= max_bytes
}

#[cfg(any(feature = "brotli", feature = "gzip", feature = "zstd"))]
enum ResponseCompressionEncoderInner {
    #[cfg(feature = "brotli")]
    Brotli(Box<Option<CompressorWriter<LimitedOutput>>>),
    #[cfg(feature = "gzip")]
    Gzip(Option<GzEncoder<LimitedOutput>>),
    #[cfg(feature = "zstd")]
    Zstd(Option<zstd::stream::write::Encoder<'static, LimitedOutput>>),
}

#[cfg(any(feature = "brotli", feature = "gzip", feature = "zstd"))]
impl std::fmt::Debug for ResponseCompressionEncoder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResponseCompressionEncoder")
            .field("encoding", &self.encoding)
            .field("total_output_bytes", &self.total_output_bytes)
            .finish_non_exhaustive()
    }
}

#[cfg(any(feature = "brotli", feature = "gzip", feature = "zstd"))]
impl ResponseCompressionEncoder {
    #[cfg(feature = "brotli")]
    pub fn brotli(quality: u32, max_output_bytes: usize) -> Self {
        Self {
            encoding: "br",
            inner: ResponseCompressionEncoderInner::Brotli(Box::new(Some(CompressorWriter::new(
                LimitedOutput::new(max_output_bytes),
                4096,
                quality,
                22,
            )))),
            total_output_bytes: 0,
        }
    }

    #[cfg(feature = "gzip")]
    pub fn gzip(level: u32, max_output_bytes: usize) -> Self {
        Self {
            encoding: "gzip",
            inner: ResponseCompressionEncoderInner::Gzip(Some(GzEncoder::new(
                LimitedOutput::new(max_output_bytes),
                Compression::new(level),
            ))),
            total_output_bytes: 0,
        }
    }

    #[cfg(feature = "zstd")]
    pub fn zstd(level: i32, max_output_bytes: usize) -> FluxResult<Self> {
        Ok(Self {
            encoding: "zstd",
            inner: ResponseCompressionEncoderInner::Zstd(Some(
                zstd::stream::write::Encoder::new(LimitedOutput::new(max_output_bytes), level)
                    .map_err(|error| {
                        FluxError::io("initialize zstd response compression", error)
                    })?,
            )),
            total_output_bytes: 0,
        })
    }

    pub fn encode_chunk(&mut self, input: Option<&[u8]>, end_of_stream: bool) -> FluxResult<Bytes> {
        match &mut self.inner {
            #[cfg(feature = "brotli")]
            ResponseCompressionEncoderInner::Brotli(encoder_slot) => {
                let Some(mut encoder) = encoder_slot.as_mut().take() else {
                    return Ok(Bytes::new());
                };
                if let Some(input) = input {
                    encoder
                        .write_all(input)
                        .map_err(|error| FluxError::io("write brotli response chunk", error))?;
                }
                let output = if end_of_stream {
                    encoder.into_inner()
                } else {
                    encoder
                        .flush()
                        .map_err(|error| FluxError::io("flush brotli response chunk", error))?;
                    let bytes =
                        take_compression_bytes(encoder.get_mut(), &mut self.total_output_bytes)?;
                    *encoder_slot.as_mut() = Some(encoder);
                    return Ok(bytes);
                };
                take_final_compression_bytes(output, &mut self.total_output_bytes)
            }
            #[cfg(feature = "gzip")]
            ResponseCompressionEncoderInner::Gzip(encoder_slot) => {
                let Some(mut encoder) = encoder_slot.take() else {
                    return Ok(Bytes::new());
                };
                if let Some(input) = input {
                    encoder
                        .write_all(input)
                        .map_err(|error| FluxError::io("write gzip response chunk", error))?;
                }
                if end_of_stream {
                    let output = encoder
                        .finish()
                        .map_err(|error| FluxError::io("finish gzip response stream", error))?;
                    take_final_compression_bytes(output, &mut self.total_output_bytes)
                } else {
                    encoder
                        .flush()
                        .map_err(|error| FluxError::io("flush gzip response chunk", error))?;
                    let bytes =
                        take_compression_bytes(encoder.get_mut(), &mut self.total_output_bytes)?;
                    *encoder_slot = Some(encoder);
                    Ok(bytes)
                }
            }
            #[cfg(feature = "zstd")]
            ResponseCompressionEncoderInner::Zstd(encoder_slot) => {
                let Some(mut encoder) = encoder_slot.take() else {
                    return Ok(Bytes::new());
                };
                if let Some(input) = input {
                    encoder
                        .write_all(input)
                        .map_err(|error| FluxError::io("write zstd response chunk", error))?;
                }
                let output = if end_of_stream {
                    encoder
                        .finish()
                        .map_err(|error| FluxError::io("finish zstd response stream", error))?
                } else {
                    encoder
                        .flush()
                        .map_err(|error| FluxError::io("flush zstd response chunk", error))?;
                    let bytes =
                        take_compression_bytes(encoder.get_mut(), &mut self.total_output_bytes)?;
                    *encoder_slot = Some(encoder);
                    return Ok(bytes);
                };
                take_final_compression_bytes(output, &mut self.total_output_bytes)
            }
        }
    }
}

#[cfg(any(feature = "brotli", feature = "gzip", feature = "zstd"))]
fn take_compression_bytes(
    output: &mut LimitedOutput,
    total_output_bytes: &mut usize,
) -> FluxResult<Bytes> {
    let bytes = output
        .take_bytes()
        .map_err(|error| FluxError::io("collect compressed response output", error))?;
    *total_output_bytes = output.total_written();
    Ok(bytes)
}

#[cfg(any(feature = "brotli", feature = "gzip", feature = "zstd"))]
fn take_final_compression_bytes(
    output: LimitedOutput,
    total_output_bytes: &mut usize,
) -> FluxResult<Bytes> {
    let (bytes, total_written) = output
        .into_bytes()
        .map_err(|error| FluxError::io("collect final compressed response output", error))?;
    *total_output_bytes = total_written;
    Ok(bytes)
}

#[cfg(test)]
#[path = "compression_tests.rs"]
mod tests;
