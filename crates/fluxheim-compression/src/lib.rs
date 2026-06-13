#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

#[cfg(any(feature = "brotli", feature = "gzip", feature = "zstd"))]
use std::io;
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
pub struct ResponseCompressionEncoder {
    pub encoding: &'static str,
    inner: ResponseCompressionEncoderInner,
    emitted: usize,
    total_output_bytes: usize,
    max_output_bytes: usize,
}

pub fn encoding_token_allows(token: &str, expected: &str) -> bool {
    let mut parts = token.split(';');
    let coding = parts.next().unwrap_or_default().trim();
    if !coding.eq_ignore_ascii_case(expected) && coding != "*" {
        return false;
    }

    for (name, value) in parts
        .map(str::trim)
        .filter_map(|parameter| parameter.split_once('='))
    {
        if !name.trim().eq_ignore_ascii_case("q") {
            continue;
        }
        let Some(quality_per_mille) = parse_accept_encoding_qvalue(value.trim()) else {
            return false;
        };
        if quality_per_mille == 0 {
            return false;
        }
    }
    true
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
    directive.eq_ignore_ascii_case("no-transform")
        || directive.eq_ignore_ascii_case("private")
        || directive.eq_ignore_ascii_case("no-store")
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

#[cfg(any(feature = "brotli", feature = "gzip", feature = "zstd"))]
enum ResponseCompressionEncoderInner {
    #[cfg(feature = "brotli")]
    Brotli(Box<Option<CompressorWriter<Vec<u8>>>>),
    #[cfg(feature = "gzip")]
    Gzip(GzEncoder<Vec<u8>>),
    #[cfg(feature = "zstd")]
    Zstd(Option<zstd::stream::write::Encoder<'static, Vec<u8>>>),
}

#[cfg(any(feature = "brotli", feature = "gzip", feature = "zstd"))]
impl std::fmt::Debug for ResponseCompressionEncoder {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResponseCompressionEncoder")
            .field("encoding", &self.encoding)
            .field("emitted", &self.emitted)
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
                Vec::new(),
                4096,
                quality,
                22,
            )))),
            emitted: 0,
            total_output_bytes: 0,
            max_output_bytes,
        }
    }

    #[cfg(feature = "gzip")]
    pub fn gzip(level: u32, max_output_bytes: usize) -> Self {
        Self {
            encoding: "gzip",
            inner: ResponseCompressionEncoderInner::Gzip(GzEncoder::new(
                Vec::new(),
                Compression::new(level),
            )),
            emitted: 0,
            total_output_bytes: 0,
            max_output_bytes,
        }
    }

    #[cfg(feature = "zstd")]
    pub fn zstd(level: i32, max_output_bytes: usize) -> FluxResult<Self> {
        Ok(Self {
            encoding: "zstd",
            inner: ResponseCompressionEncoderInner::Zstd(Some(
                zstd::stream::write::Encoder::new(Vec::new(), level).map_err(|error| {
                    FluxError::io("initialize zstd response compression", error)
                })?,
            )),
            emitted: 0,
            total_output_bytes: 0,
            max_output_bytes,
        })
    }

    pub fn encode_chunk(
        &mut self,
        input: Option<&Bytes>,
        end_of_stream: bool,
    ) -> FluxResult<Bytes> {
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
                    let bytes = take_new_compression_bytes(
                        encoder.get_mut(),
                        &mut self.emitted,
                        &mut self.total_output_bytes,
                        self.max_output_bytes,
                    )?;
                    *encoder_slot.as_mut() = Some(encoder);
                    return Ok(bytes);
                };
                take_final_compression_bytes(
                    output,
                    &mut self.emitted,
                    &mut self.total_output_bytes,
                    self.max_output_bytes,
                )
            }
            #[cfg(feature = "gzip")]
            ResponseCompressionEncoderInner::Gzip(encoder) => {
                if let Some(input) = input {
                    encoder
                        .write_all(input)
                        .map_err(|error| FluxError::io("write gzip response chunk", error))?;
                }
                if end_of_stream {
                    encoder
                        .try_finish()
                        .map_err(|error| FluxError::io("finish gzip response stream", error))?;
                } else {
                    encoder
                        .flush()
                        .map_err(|error| FluxError::io("flush gzip response chunk", error))?;
                }
                take_new_compression_bytes(
                    encoder.get_mut(),
                    &mut self.emitted,
                    &mut self.total_output_bytes,
                    self.max_output_bytes,
                )
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
                    let bytes = take_new_compression_bytes(
                        encoder.get_mut(),
                        &mut self.emitted,
                        &mut self.total_output_bytes,
                        self.max_output_bytes,
                    )?;
                    *encoder_slot = Some(encoder);
                    return Ok(bytes);
                };
                take_final_compression_bytes(
                    output,
                    &mut self.emitted,
                    &mut self.total_output_bytes,
                    self.max_output_bytes,
                )
            }
        }
    }
}

#[cfg(any(feature = "brotli", feature = "gzip", feature = "zstd"))]
fn take_new_compression_bytes(
    output: &mut Vec<u8>,
    emitted: &mut usize,
    total_output_bytes: &mut usize,
    max_output_bytes: usize,
) -> FluxResult<Bytes> {
    let Some(new_len) = output.len().checked_sub(*emitted) else {
        return Err(compressed_response_exceeds_limit_error());
    };
    ensure_compressed_output_within_limit(new_len, total_output_bytes, max_output_bytes)?;
    let bytes = Bytes::copy_from_slice(&output[*emitted..]);
    *output = Vec::new();
    *emitted = 0;
    Ok(bytes)
}

#[cfg(any(feature = "brotli", feature = "zstd"))]
fn take_final_compression_bytes(
    output: Vec<u8>,
    emitted: &mut usize,
    total_output_bytes: &mut usize,
    max_output_bytes: usize,
) -> FluxResult<Bytes> {
    let Some(new_len) = output.len().checked_sub(*emitted) else {
        return Err(compressed_response_exceeds_limit_error());
    };
    ensure_compressed_output_within_limit(new_len, total_output_bytes, max_output_bytes)?;
    let bytes = Bytes::copy_from_slice(&output[*emitted..]);
    *emitted = 0;
    Ok(bytes)
}

#[cfg(any(feature = "brotli", feature = "gzip", feature = "zstd"))]
fn ensure_compressed_output_within_limit(
    new_len: usize,
    total_output_bytes: &mut usize,
    max_output_bytes: usize,
) -> FluxResult<()> {
    let Some(next_total) = total_output_bytes.checked_add(new_len) else {
        return Err(compressed_response_exceeds_limit_error());
    };
    if next_total > max_output_bytes {
        return Err(compressed_response_exceeds_limit_error());
    }
    *total_output_bytes = next_total;
    Ok(())
}

#[cfg(any(feature = "brotli", feature = "gzip", feature = "zstd"))]
fn compressed_response_exceeds_limit_error() -> FluxError {
    FluxError::io(
        "compressed response exceeds max_output_bytes",
        io::Error::new(
            io::ErrorKind::InvalidData,
            "compressed response exceeds max_output_bytes",
        ),
    )
}

#[cfg(test)]
mod tests {
    use super::{
        cache_control_directive_blocks_compression, content_type_is_compressible,
        encoding_token_allows, parse_accept_encoding_qvalue,
    };

    #[cfg(feature = "gzip")]
    use std::io;

    #[cfg(feature = "gzip")]
    use bytes::Bytes;

    #[cfg(feature = "gzip")]
    use super::{ResponseCompressionEncoder, ResponseCompressionEncoderInner};

    #[test]
    fn parses_accept_encoding_qvalues() {
        assert_eq!(parse_accept_encoding_qvalue("0"), Some(0));
        assert_eq!(parse_accept_encoding_qvalue("0.125"), Some(125));
        assert_eq!(parse_accept_encoding_qvalue("1"), Some(1000));
        assert_eq!(parse_accept_encoding_qvalue("1.000"), Some(1000));
        assert_eq!(parse_accept_encoding_qvalue("1.001"), None);
        assert_eq!(parse_accept_encoding_qvalue("0.0000"), None);
        assert_eq!(parse_accept_encoding_qvalue("NaN"), None);
    }

    #[test]
    fn parses_accept_encoding_tokens() {
        assert!(encoding_token_allows("gzip", "gzip"));
        assert!(encoding_token_allows("GZIP;q=1.0", "gzip"));
        assert!(encoding_token_allows("*;q=0.5", "br"));
        assert!(!encoding_token_allows("br;q=0", "br"));
        assert!(!encoding_token_allows("gzip;q=banana", "gzip"));
        assert!(!encoding_token_allows("br", "gzip"));
    }

    #[test]
    fn classifies_compression_response_policy_tokens() {
        assert!(cache_control_directive_blocks_compression("no-transform"));
        assert!(cache_control_directive_blocks_compression("PRIVATE"));
        assert!(!cache_control_directive_blocks_compression("max-age=60"));

        assert!(content_type_is_compressible("text/plain; charset=utf-8"));
        assert!(content_type_is_compressible("application/json"));
        assert!(content_type_is_compressible("image/svg+xml"));
        assert!(!content_type_is_compressible("image/png"));
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn gzip_encoder_releases_retained_output_between_chunks() {
        let mut encoder = ResponseCompressionEncoder::gzip(0, 4096);
        let first = encoder
            .encode_chunk(Some(&Bytes::from(vec![b'a'; 1024])), false)
            .expect("first gzip chunk should encode");
        assert!(!first.is_empty());
        assert!(encoder.total_output_bytes >= first.len());
        let ResponseCompressionEncoderInner::Gzip(gzip) = &encoder.inner else {
            panic!("expected gzip encoder");
        };
        assert_eq!(gzip.get_ref().len(), 0);

        let second = encoder
            .encode_chunk(Some(&Bytes::from(vec![b'b'; 1024])), false)
            .expect("second gzip chunk should encode");
        assert!(!second.is_empty());
        assert!(encoder.total_output_bytes >= first.len() + second.len());
        let ResponseCompressionEncoderInner::Gzip(gzip) = &encoder.inner else {
            panic!("expected gzip encoder");
        };
        assert_eq!(gzip.get_ref().len(), 0);
    }

    #[cfg(feature = "gzip")]
    #[test]
    fn gzip_encoder_limit_counts_released_output_cumulatively() {
        let mut encoder = ResponseCompressionEncoder::gzip(0, 4096);
        let first = encoder
            .encode_chunk(Some(&Bytes::from(vec![b'a'; 1024])), false)
            .expect("first gzip chunk should encode");
        assert!(!first.is_empty());
        encoder.max_output_bytes = encoder.total_output_bytes + 1;

        let error = encoder
            .encode_chunk(Some(&Bytes::from(vec![b'b'; 1024])), true)
            .expect_err("gzip output should exceed configured limit");
        assert_eq!(error.io_kind(), Some(io::ErrorKind::InvalidData));
    }
}
