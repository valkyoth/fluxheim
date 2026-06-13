#![forbid(unsafe_code)]
#![cfg_attr(
    not(test),
    deny(clippy::expect_used, clippy::panic, clippy::unwrap_used)
)]

use std::fmt::Write as _;

#[cfg(feature = "otlp-http")]
pub use otlp_http::agent;
#[cfg(feature = "otlp-trace")]
pub use otlp_trace::{TraceExporter, TraceSpan};

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

#[cfg(feature = "otlp-http")]
mod otlp_http {
    use std::fs::OpenOptions;
    use std::io::{self, Read};
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::Path;
    use std::time::Duration;

    #[cfg(any(target_os = "linux", target_os = "android"))]
    const O_NOFOLLOW: i32 = 0o400000;

    #[cfg(any(
        target_os = "macos",
        target_os = "ios",
        target_os = "freebsd",
        target_os = "netbsd",
        target_os = "openbsd",
        target_os = "dragonfly"
    ))]
    const O_NOFOLLOW: i32 = 0x0100;

    #[cfg(all(
        unix,
        not(any(
            target_os = "linux",
            target_os = "android",
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "netbsd",
            target_os = "openbsd",
            target_os = "dragonfly"
        ))
    ))]
    compile_error!(
        "O_NOFOLLOW is unknown on this Unix platform; audit symlink-safe OTLP CA loading before building Fluxheim"
    );

    const MAX_OTLP_CA_CERT_BYTES: u64 = 1024 * 1024;

    pub fn agent(timeout: Duration, tls_ca_cert_path: Option<&Path>) -> io::Result<ureq::Agent> {
        let mut builder = ureq::Agent::config_builder()
            .timeout_global(Some(timeout))
            .max_redirects(0)
            .http_status_as_error(false);

        if let Some(path) = tls_ca_cert_path {
            let certs = load_ca_certificates(path)?;
            builder = builder.tls_config(
                ureq::tls::TlsConfig::builder()
                    .root_certs(ureq::tls::RootCerts::new_with_certs(&certs))
                    .build(),
            );
        }

        Ok(builder.build().into())
    }

    fn load_ca_certificates(path: &Path) -> io::Result<Vec<ureq::tls::Certificate<'static>>> {
        let mut options = OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        options.custom_flags(O_NOFOLLOW);
        let file = options.open(path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "failed to read OTLP TLS CA certificate {}: {error}",
                    path.display()
                ),
            )
        })?;
        let metadata = file.metadata().map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "failed to inspect OTLP TLS CA certificate {}: {error}",
                    path.display()
                ),
            )
        })?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "OTLP TLS CA certificate {} is not a regular file",
                    path.display()
                ),
            ));
        }

        let mut contents = Vec::new();
        let mut limited = file.take(MAX_OTLP_CA_CERT_BYTES.saturating_add(1));
        limited.read_to_end(&mut contents).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "failed to read OTLP TLS CA certificate {}: {error}",
                    path.display()
                ),
            )
        })?;
        if contents.len() as u64 > MAX_OTLP_CA_CERT_BYTES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "OTLP TLS CA certificate {} exceeds {} bytes",
                    path.display(),
                    MAX_OTLP_CA_CERT_BYTES
                ),
            ));
        }
        let mut certificates = Vec::new();
        for item in ureq::tls::parse_pem(&contents) {
            match item {
                Ok(ureq::tls::PemItem::Certificate(certificate)) => {
                    certificates.push(certificate);
                }
                Ok(_) => {}
                Err(error) => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "failed to parse OTLP TLS CA certificate {}: {error}",
                            path.display()
                        ),
                    ));
                }
            }
        }
        if certificates.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "OTLP TLS CA certificate {} did not contain any PEM certificates",
                    path.display()
                ),
            ));
        }
        Ok(certificates)
    }

    #[cfg(test)]
    mod tests {
        use super::load_ca_certificates;

        #[cfg(unix)]
        #[test]
        fn rejects_symlinked_ca_certificate() {
            let target = fluxheim_common::test_support::unique_temp_path("otlp-ca-target");
            let link = fluxheim_common::test_support::unique_temp_path("otlp-ca-link");
            std::fs::write(&target, b"not a certificate\n").expect("write target");
            std::os::unix::fs::symlink(&target, &link).expect("create symlink");

            let error = load_ca_certificates(&link).expect_err("symlink must be rejected");

            assert_ne!(error.kind(), std::io::ErrorKind::InvalidData);
            assert!(error.to_string().contains("failed to read"));
            let _ = std::fs::remove_file(target);
            let _ = std::fs::remove_file(link);
        }
    }
}

#[cfg(feature = "otlp-trace")]
mod otlp_trace;

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
