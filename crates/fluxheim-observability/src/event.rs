//! Bounded, allowlisted event capture. This module does not log, queue or perform I/O.
//!
//! Existing free-form runtime logs are NOT sanitized by this API. Owners must map
//! failures to typed codes before capture; raw errors, headers, URLs and bodies
//! deliberately have no representation here.
//!
//! Raw errors (including arbitrary nested sources) cannot be assigned as reasons:
//! ```compile_fail
//! use fluxheim_observability::event::EventData;
//! let error = std::io::Error::other("authorization=secret");
//! let data = EventData::Error { reason: error, attempt: None };
//! ```

use serde::Serialize;

#[path = "event_encode.rs"]
mod encode;
#[path = "event_types.rs"]
mod types;
pub use encode::{EncodedEvent, EncodingError, EventFormat};
pub use types::*;

pub const SCHEMA_VERSION: u8 = 1;
pub const MAX_EVENT_BYTES: usize = 8192;
pub const MAX_EVENT_FIELDS: usize = 32;
pub const MAX_STRING_BYTES: usize = 1024;
pub const MAX_MESSAGE_BYTES: usize = 4096;
pub const MAX_REQUEST_ID_BYTES: usize = 128;

/// Privacy restrictions intersect with, and never loosen, the effective log filter.
/// The runtime supplies the filter result after resolving RUST_LOG/configuration,
/// including any message regex against the fixed message, before capture.
#[derive(Debug, Clone, Copy, Default)]
pub struct CapturePolicy {
    pub access_enabled: bool,
    pub include_resource: bool,
    pub include_request_id: bool,
    pub include_trace_ids: bool,
    pub privacy_mode: bool,
}

impl CapturePolicy {
    fn private(self) -> bool {
        self.privacy_mode || cfg!(feature = "privacy-mode")
    }

    pub fn allows(self, data: EventData, filter_enabled: bool) -> bool {
        filter_enabled
            && (!matches!(data, EventData::Access { .. })
                || (self.access_enabled && !self.private()))
    }
}

/// Borrowed candidates: rejected input is never copied or formatted. `trusted`
/// must come from the runtime's local-ID/trusted-peer policy, not an HTTP header.
/// Syntax validation is not authentication or detection of secrets in valid IDs.
#[derive(Default)]
pub struct CorrelationInput<'a> {
    pub trusted: bool,
    pub request_id: Option<&'a str>,
    pub trace_id: Option<&'a str>,
    pub span_id: Option<&'a str>,
}

impl std::fmt::Debug for CorrelationInput<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("CorrelationInput([REDACTED])")
    }
}

#[derive(Debug, Default, Serialize)]
struct Correlation {
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    trace_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    span_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct StructuredEvent {
    schema_version: u8,
    service_version: &'static str,
    timestamp_unix_nanos: u64,
    level: &'static str,
    message: &'static str,
    data: EventData,
    #[serde(skip_serializing_if = "Option::is_none")]
    resource: Option<ResourceId>,
    correlation: Correlation,
    redacted: bool,
    truncated: bool,
}

impl StructuredEvent {
    pub fn capture(
        timestamp_unix_nanos: u64,
        data: EventData,
        resource: Option<ResourceId>,
        input: CorrelationInput<'_>,
        policy: CapturePolicy,
        filter_enabled: bool,
    ) -> Option<Self> {
        if !policy.allows(data, filter_enabled) {
            return None;
        }
        let mut event = Self {
            schema_version: SCHEMA_VERSION,
            service_version: env!("CARGO_PKG_VERSION"),
            timestamp_unix_nanos,
            level: data.level().as_str(),
            message: data.message(),
            data,
            resource: None,
            correlation: Correlation::default(),
            redacted: false,
            truncated: false,
        };
        if policy.include_resource && !policy.private() {
            event.resource = resource;
        } else {
            event.redacted |= resource.is_some();
        }
        if !input.trusted || policy.private() {
            event.redacted |=
                input.request_id.is_some() || input.trace_id.is_some() || input.span_id.is_some();
            return Some(event);
        }
        if let Some(id) = input.request_id {
            if !policy.include_request_id {
                event.redacted = true;
            } else if id.len() > MAX_REQUEST_ID_BYTES {
                event.redacted = true;
                event.truncated = true;
            } else if crate::access_log_request_id_valid(id) {
                event.correlation.request_id = Some(id.to_owned());
            } else {
                event.redacted = true;
            }
        }
        if input.trace_id.is_some() || input.span_id.is_some() {
            if !policy.include_trace_ids {
                event.redacted = true;
            } else {
                match (input.trace_id, input.span_id) {
                    (Some(trace), Some(span))
                        if valid_hex_id(trace, 32) && valid_hex_id(span, 16) =>
                    {
                        event.correlation.trace_id = Some(trace.to_ascii_lowercase());
                        event.correlation.span_id = Some(span.to_ascii_lowercase());
                    }
                    _ => {
                        event.redacted = true;
                        event.truncated |= input.trace_id.is_some_and(|v| v.len() > 32)
                            || input.span_id.is_some_and(|v| v.len() > 16);
                    }
                }
            }
        }
        Some(event)
    }

    pub fn admission_class(&self) -> AdmissionClass {
        self.data.admission_class()
    }
}

fn valid_hex_id(value: &str, length: usize) -> bool {
    value.len() == length
        && value.bytes().all(|b| b.is_ascii_hexdigit())
        && value.bytes().any(|b| b != b'0')
}

#[cfg(test)]
#[path = "event_tests.rs"]
mod tests;
