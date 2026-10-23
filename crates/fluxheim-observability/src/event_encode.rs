use super::{MAX_EVENT_BYTES, StructuredEvent};
use std::io::{self, Write as _};

#[derive(Debug, Clone, Copy)]
pub enum EventFormat {
    Json,
    Text,
}

/// Owned queue-ready bytes including exactly one terminating newline.
/// The size includes text framing; callers must not add an unaccounted envelope.
#[derive(Debug)]
pub struct EncodedEvent {
    bytes: Box<[u8]>,
}

impl EncodedEvent {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn encoded_len(&self) -> usize {
        self.bytes.len()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EncodingError {
    SizeLimit,
    Serialization,
}

impl std::fmt::Display for EncodingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::SizeLimit => "structured event exceeds its encoded byte limit",
            Self::Serialization => "structured event serialization failed",
        })
    }
}

impl std::error::Error for EncodingError {}

impl StructuredEvent {
    pub fn encode(&self, format: EventFormat) -> Result<EncodedEvent, EncodingError> {
        self.encode_with_limit(format, MAX_EVENT_BYTES)
    }

    pub(super) fn encode_with_limit(
        &self,
        format: EventFormat,
        limit: usize,
    ) -> Result<EncodedEvent, EncodingError> {
        let limit = limit.min(MAX_EVENT_BYTES);
        let mut writer = BoundedWriter {
            bytes: Vec::with_capacity(limit),
            limit,
            exceeded: false,
        };
        let result = (|| -> io::Result<()> {
            if matches!(format, EventFormat::Text) {
                write!(writer, "{} {} ", self.level, self.data.kind())?;
            }
            // Both formats serialize the same already-redacted model. No Display/Error fallback.
            serde_json::to_writer(&mut writer, self).map_err(io::Error::other)?;
            writer.write_all(b"\n")
        })();
        if writer.exceeded {
            return Err(EncodingError::SizeLimit);
        }
        result.map_err(|_| EncodingError::Serialization)?;
        Ok(EncodedEvent {
            bytes: writer.bytes.into_boxed_slice(),
        })
    }
}

struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

impl io::Write for BoundedWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit.saturating_sub(self.bytes.len()) {
            self.exceeded = true;
            return Err(io::Error::other("event byte limit"));
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn escaping_expansion_cannot_grow_the_buffer_past_the_limit() {
        for text in [
            "\u{0001}".repeat(MAX_EVENT_BYTES),
            "\"\\\n".repeat(MAX_EVENT_BYTES),
            "\u{00e9}".repeat(MAX_EVENT_BYTES),
        ] {
            let mut writer = BoundedWriter {
                bytes: Vec::with_capacity(MAX_EVENT_BYTES),
                limit: MAX_EVENT_BYTES,
                exceeded: false,
            };
            assert!(serde_json::to_writer(&mut writer, &text).is_err());
            assert!(writer.exceeded);
            assert!(writer.bytes.len() <= MAX_EVENT_BYTES);
            assert_eq!(writer.bytes.capacity(), MAX_EVENT_BYTES);
        }
    }
}
