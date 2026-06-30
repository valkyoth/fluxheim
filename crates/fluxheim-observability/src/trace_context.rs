use std::fmt::Write as _;

const TRACEPARENT_VERSION: &str = "00";
const TRACE_ID_HEX_LEN: usize = 32;
const SPAN_ID_HEX_LEN: usize = 16;
const FLAGS_HEX_LEN: usize = 2;
const TRACEPARENT_LEN: usize = 2 + 1 + TRACE_ID_HEX_LEN + 1 + SPAN_ID_HEX_LEN + 1 + FLAGS_HEX_LEN;
const SAMPLED_FLAG: u8 = 0x01;
const RANDOM_ID_ATTEMPTS: usize = 8;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TraceContext {
    trace_id: [u8; 16],
    span_id: [u8; 8],
    parent_span_id: Option<[u8; 8]>,
    flags: u8,
}

impl TraceContext {
    pub fn generate() -> Option<Self> {
        Some(Self {
            trace_id: non_zero_random_16()?,
            span_id: non_zero_random_8()?,
            parent_span_id: None,
            flags: 0,
        })
    }

    pub fn parse_traceparent(value: &str, trusted_peer: bool) -> Option<Self> {
        let value = value.trim();
        if value.len() != TRACEPARENT_LEN {
            return None;
        }
        let bytes = value.as_bytes();
        if bytes.get(0..2)? != TRACEPARENT_VERSION.as_bytes()
            || bytes.get(2) != Some(&b'-')
            || bytes.get(35) != Some(&b'-')
            || bytes.get(52) != Some(&b'-')
        {
            return None;
        }

        let trace_id = parse_hex_array::<16>(&value[3..35])?;
        if trace_id.iter().all(|byte| *byte == 0) {
            return None;
        }
        let span_id = parse_hex_array::<8>(&value[36..52])?;
        if span_id.iter().all(|byte| *byte == 0) {
            return None;
        }
        let regenerated_span_id = non_zero_random_8()?;
        let flags = parse_hex_byte(&value[53..55])?;
        Some(Self {
            trace_id,
            span_id: regenerated_span_id,
            parent_span_id: Some(span_id),
            flags: if trusted_peer {
                flags & SAMPLED_FLAG
            } else {
                0
            },
        })
    }

    pub fn trace_id_hex(&self) -> String {
        hex_bytes(&self.trace_id)
    }

    pub fn span_id_hex(&self) -> String {
        hex_bytes(&self.span_id)
    }

    pub fn parent_span_id_hex(&self) -> Option<String> {
        self.parent_span_id.map(|span_id| hex_bytes(&span_id))
    }

    pub fn to_traceparent(self) -> String {
        format!(
            "{TRACEPARENT_VERSION}-{}-{}-{:02x}",
            hex_bytes(&self.trace_id),
            hex_bytes(&self.span_id),
            self.flags & SAMPLED_FLAG
        )
    }
}

pub fn context_from_traceparent(value: Option<&str>, trusted_peer: bool) -> Option<TraceContext> {
    value
        .and_then(|value| TraceContext::parse_traceparent(value, trusted_peer))
        .or_else(TraceContext::generate)
}

fn non_zero_random_16() -> Option<[u8; 16]> {
    for _ in 0..RANDOM_ID_ATTEMPTS {
        let mut bytes = [0_u8; 16];
        if getrandom::fill(&mut bytes).is_ok() && bytes.iter().any(|byte| *byte != 0) {
            return Some(bytes);
        }
    }
    log::error!("trace context: CSPRNG unavailable after {RANDOM_ID_ATTEMPTS} attempts");
    None
}

fn non_zero_random_8() -> Option<[u8; 8]> {
    for _ in 0..RANDOM_ID_ATTEMPTS {
        let mut bytes = [0_u8; 8];
        if getrandom::fill(&mut bytes).is_ok() && bytes.iter().any(|byte| *byte != 0) {
            return Some(bytes);
        }
    }
    log::error!("trace context: CSPRNG unavailable after {RANDOM_ID_ATTEMPTS} attempts");
    None
}

fn parse_hex_array<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut bytes = [0_u8; N];
    for index in 0..N {
        bytes[index] = parse_hex_byte(&value[index * 2..index * 2 + 2])?;
    }
    Some(bytes)
}

fn parse_hex_byte(value: &str) -> Option<u8> {
    let bytes = value.as_bytes();
    if bytes.len() != 2 {
        return None;
    }
    let high = hex_nibble(bytes[0])?;
    let low = hex_nibble(bytes[1])?;
    Some((high << 4) | low)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

fn hex_bytes(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(&mut output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_traceparent_and_regenerates_span_id() {
        let context = TraceContext::parse_traceparent(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            true,
        )
        .expect("valid traceparent should parse");

        assert_eq!(context.trace_id_hex(), "4bf92f3577b34da6a3ce929d0e0e4736");
        assert!(
            context
                .to_traceparent()
                .starts_with("00-4bf92f3577b34da6a3ce929d0e0e4736-")
        );
        assert!(context.to_traceparent().ends_with("-01"));
        assert!(!context.to_traceparent().contains("-00f067aa0ba902b7-"));
    }

    #[test]
    fn clears_untrusted_sampled_flag() {
        let context = TraceContext::parse_traceparent(
            "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01",
            false,
        )
        .expect("valid traceparent should parse");

        assert!(context.to_traceparent().ends_with("-00"));
    }

    #[test]
    fn rejects_malformed_or_zero_traceparent() {
        assert!(TraceContext::parse_traceparent("bad", true).is_none());
        assert!(
            TraceContext::parse_traceparent(
                "00-00000000000000000000000000000000-00f067aa0ba902b7-01",
                true,
            )
            .is_none()
        );
        assert!(
            TraceContext::parse_traceparent(
                "00-4bf92f3577b34da6a3ce929d0e0e4736-0000000000000000-01",
                true,
            )
            .is_none()
        );
    }

    #[test]
    fn generates_non_zero_context() {
        let context = TraceContext::generate().expect("trace context should generate");

        assert_ne!(context.trace_id_hex(), "00000000000000000000000000000000");
        assert_eq!(context.to_traceparent().len(), TRACEPARENT_LEN);
    }
}
