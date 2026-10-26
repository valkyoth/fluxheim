//! Bounded OTLP/HTTP delivery. Never exposes collector bodies, URLs or credentials in errors.
use std::io::{self, Read};
use std::path::Path;
use std::time::Duration;
use zeroize::Zeroizing;

thread_local! {
    static IN_DELIVERY: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// HTTP client debug logs can include collector-controlled headers. The runtime
/// logger checks this before formatting, regardless of the configured log level.
pub fn export_diagnostics_suppressed() -> bool {
    IN_DELIVERY.try_with(std::cell::Cell::get).unwrap_or(true)
}
struct DiagnosticScope(bool);
impl DiagnosticScope {
    fn enter() -> Self {
        Self(IN_DELIVERY.with(|active| active.replace(true)))
    }
}
impl Drop for DiagnosticScope {
    fn drop(&mut self) {
        let _ = IN_DELIVERY.try_with(|active| active.set(self.0));
    }
}

pub const MAX_EXPORT_BYTES: usize = 4 * 1024 * 1024;
pub const MAX_REPLY_BYTES: u64 = 16 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportSignal {
    Traces,
    Metrics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExportOutcome {
    Success,
    Partial,
    Rejected,
    Malformed,
    Transport,
    Retry(Duration),
}

pub(super) struct Delivery {
    agent: ureq::Agent,
    endpoint: String,
    authorization: Option<Zeroizing<String>>,
    signal: ExportSignal,
}

impl Delivery {
    pub(super) fn new(
        endpoint: &str,
        ca: Option<&Path>,
        token: Option<&Path>,
        signal: ExportSignal,
    ) -> io::Result<Self> {
        crate::OtlpHttpEndpoint::parse(endpoint)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid OTLP endpoint"))?;
        if token.is_some() && !endpoint.starts_with("https://") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "OTLP credentials require HTTPS",
            ));
        }
        let authorization = token.map(load_token).transpose()?;
        Ok(Self {
            agent: crate::agent(Duration::from_secs(2), ca)?,
            endpoint: endpoint.to_owned(),
            authorization,
            signal,
        })
    }

    pub(super) fn post(&self, payload: &str, timeout: Duration) -> ExportOutcome {
        let _diagnostics = DiagnosticScope::enter();
        if payload.len() > MAX_EXPORT_BYTES || timeout.is_zero() {
            return ExportOutcome::Rejected;
        }
        let mut request = self
            .agent
            .post(&self.endpoint)
            .config()
            .timeout_global(Some(timeout))
            .build()
            .header("content-type", "application/json");
        if let Some(token) = &self.authorization {
            request = request.header("authorization", token.as_str());
        }
        let mut response = match request.send(payload) {
            Ok(response) => response,
            Err(ureq::Error::Io(error)) if error.kind() == io::ErrorKind::InvalidData => {
                return ExportOutcome::Rejected;
            }
            Err(
                ureq::Error::Rustls(_)
                | ureq::Error::Tls(_)
                | ureq::Error::TooManyRedirects
                | ureq::Error::LargeResponseHeader(_, _),
            ) => return ExportOutcome::Rejected,
            Err(_) => return ExportOutcome::Transport,
        };
        let status = response.status().as_u16();
        if matches!(status, 429 | 502 | 503 | 504) {
            let seconds = response
                .headers()
                .get("retry-after")
                .and_then(|h| h.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
                .unwrap_or(0);
            return ExportOutcome::Retry(Duration::from_secs(seconds.min(60)));
        }
        if status != 200 {
            return ExportOutcome::Rejected;
        }
        let Ok(body) = response
            .body_mut()
            .with_config()
            .limit(MAX_REPLY_BYTES)
            .read_to_vec()
        else {
            return ExportOutcome::Malformed;
        };
        parse_response(&body, self.signal)
    }
}

fn load_token(path: &Path) -> io::Result<Zeroizing<String>> {
    let file = fluxheim_config::fs_trust::open_confidential_file(path).map_err(|_| {
        io::Error::new(
            io::ErrorKind::PermissionDenied,
            "cannot securely open OTLP token file",
        )
    })?;
    let mut bytes = Zeroizing::new(Vec::new());
    file.take(4097).read_to_end(&mut bytes)?;
    if bytes.len() > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "OTLP token exceeds limit",
        ));
    }
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid OTLP token"))?;
    let text = text.trim_end_matches(['\r', '\n']);
    if text.is_empty() || !text.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid OTLP token",
        ));
    }
    Ok(Zeroizing::new(format!("Bearer {text}")))
}

fn parse_response(body: &[u8], signal: ExportSignal) -> ExportOutcome {
    if body.is_empty() {
        return ExportOutcome::Success;
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return ExportOutcome::Malformed;
    };
    if !value.is_object() {
        return ExportOutcome::Malformed;
    }
    let Some(partial) = value.get("partialSuccess") else {
        return ExportOutcome::Success;
    };
    if !partial.is_object() {
        return ExportOutcome::Malformed;
    }
    let field = match signal {
        ExportSignal::Traces => "rejectedSpans",
        ExportSignal::Metrics => "rejectedDataPoints",
    };
    let rejected = match partial.get(field) {
        None => 0,
        Some(value) => match value
            .as_u64()
            .or_else(|| value.as_str().and_then(|v| v.parse::<u64>().ok()))
        {
            Some(count) => count,
            None => return ExportOutcome::Malformed,
        },
    };
    let message = match partial.get("errorMessage") {
        None => "",
        Some(value) => match value.as_str() {
            Some(text) => text,
            None => return ExportOutcome::Malformed,
        },
    };
    if rejected > 0 || !message.is_empty() {
        ExportOutcome::Partial
    } else {
        ExportOutcome::Success
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn diagnostic_suppression_is_scoped_and_thread_local() {
        assert!(!export_diagnostics_suppressed());
        {
            let _scope = DiagnosticScope::enter();
            assert!(export_diagnostics_suppressed());
            {
                let _nested = DiagnosticScope::enter();
                assert!(export_diagnostics_suppressed());
            }
            assert!(export_diagnostics_suppressed());
            assert!(
                !std::thread::spawn(export_diagnostics_suppressed)
                    .join()
                    .unwrap()
            );
        }
        assert!(!export_diagnostics_suppressed());
    }
    #[test]
    fn response_contract_is_strict_and_does_not_echo_errors() {
        for body in [
            "[]",
            "null",
            "{",
            "{\"partialSuccess\":null}",
            "{\"partialSuccess\":{\"rejectedSpans\":-1}}",
            "{\"partialSuccess\":{\"errorMessage\":42}}",
        ] {
            assert_eq!(
                parse_response(body.as_bytes(), ExportSignal::Traces),
                ExportOutcome::Malformed
            );
        }
        for body in [
            "",
            "{}",
            "{\"partialSuccess\":{}}",
            "{\"partialSuccess\":{\"rejectedSpans\":\"0\"}}",
        ] {
            assert_eq!(
                parse_response(body.as_bytes(), ExportSignal::Traces),
                ExportOutcome::Success
            );
        }
        assert_eq!(
            parse_response(
                br#"{"partialSuccess":{"rejectedDataPoints":"1","errorMessage":"secret-canary"}}"#,
                ExportSignal::Metrics
            ),
            ExportOutcome::Partial
        );
        assert_eq!(
            parse_response(
                br#"{"partialSuccess":{"errorMessage":"warning"}}"#,
                ExportSignal::Traces
            ),
            ExportOutcome::Partial
        );
    }
    #[test]
    fn credentials_require_https_before_any_file_read() {
        let error = Delivery::new(
            "http://127.0.0.1/v1/traces",
            None,
            Some(Path::new("secret-canary")),
            ExportSignal::Traces,
        )
        .err()
        .unwrap();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(!error.to_string().contains("secret-canary"));
    }
}

#[cfg(test)]
#[path = "otlp_tls_tests.rs"]
mod tls_tests;
