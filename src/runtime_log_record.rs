use std::fmt::{self, Write as _};
use std::io;
use std::time::SystemTime;

pub(super) const MAX_MESSAGE: usize = 4096;
pub(super) const MAX_TARGET: usize = 1024;
pub(super) const MAX_ENCODED: usize = 8192;

pub(super) struct Buffer<const N: usize> {
    bytes: [u8; N],
    len: usize,
    failed: bool,
}

impl<const N: usize> Buffer<N> {
    pub(super) fn new() -> Self {
        Self {
            bytes: [0; N],
            len: 0,
            failed: false,
        }
    }
    pub(super) fn as_str(&self) -> &str {
        // All appends are complete UTF-8 strings; no byte truncation.
        std::str::from_utf8(&self.bytes[..self.len]).unwrap_or("")
    }
}

impl<const N: usize> fmt::Write for Buffer<N> {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        if value.len() > N.saturating_sub(self.len) {
            self.failed = true;
            return Err(fmt::Error);
        }
        self.bytes[self.len..self.len + value.len()].copy_from_slice(value.as_bytes());
        self.len += value.len();
        Ok(())
    }
}

pub(super) struct Record {
    pub(super) timestamp: SystemTime,
    pub(super) level: log::Level,
    pub(super) target: Buffer<MAX_TARGET>,
    pub(super) message: Buffer<MAX_MESSAGE>,
}

impl Record {
    pub(super) fn capture(record: &log::Record<'_>) -> Result<Self, fmt::Error> {
        let mut target = Buffer::new();
        target.write_str(record.target())?;
        let mut message = Buffer::new();
        message.write_fmt(*record.args())?;
        if message.failed {
            return Err(fmt::Error);
        }
        Ok(Self {
            timestamp: SystemTime::now(),
            level: record.level(),
            target,
            message,
        })
    }

    pub(super) fn encode(
        &self,
        format: crate::config::LoggingFormat,
    ) -> io::Result<Buffer<MAX_ENCODED>> {
        let timestamp = jiff::Timestamp::try_from(self.timestamp).map_err(io::Error::other)?;
        let mut out = Buffer::new();
        let result = match format {
            crate::config::LoggingFormat::Json => (|| {
                write!(
                    out,
                    "{{\"timestamp\":\"{timestamp:.3}\",\"level\":\"{}\",\"target\":\"",
                    self.level
                )?;
                escaped(&mut out, self.target.as_str())?;
                out.write_str("\",\"message\":\"")?;
                escaped(&mut out, self.message.as_str())?;
                out.write_str("\"}\n")
            })(),
            crate::config::LoggingFormat::Text => (|| {
                write!(out, "{timestamp:.3} {} ", self.level)?;
                escaped(&mut out, self.target.as_str())?;
                out.write_str(": ")?;
                escaped(&mut out, self.message.as_str())?;
                out.write_char('\n')
            })(),
        };
        result.map_err(|_| io::Error::other("log record exceeds encoded byte limit"))?;
        Ok(out)
    }
}

// Escape even text records to prevent attacker-controlled line/terminal injection.
fn escaped(out: &mut impl fmt::Write, text: &str) -> fmt::Result {
    for ch in text.chars() {
        match ch {
            '"' => out.write_str("\\\"")?,
            '\\' => out.write_str("\\\\")?,
            '\n' => out.write_str("\\n")?,
            '\r' => out.write_str("\\r")?,
            '\t' => out.write_str("\\t")?,
            ch if ch.is_control() || matches!(ch, '\u{2028}' | '\u{2029}') => {
                write!(out, "\\u{:04x}", ch as u32)?
            }
            ch => out.write_char(ch)?,
        }
    }
    Ok(())
}
