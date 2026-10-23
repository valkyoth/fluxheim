use serde::Serialize;

/// Closed event families. No caller-provided message, error chain or field map.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EventData {
    Access {
        outcome: AccessOutcome,
        method: Method,
        status: Option<HttpStatus>,
        duration_micros: u64,
        bytes_sent: u64,
        attempts: u32,
    },
    Error {
        reason: FailureReason,
        attempt: Option<u32>,
    },
    Security {
        reason: SecurityReason,
    },
    Audit {
        operation: AuditOperation,
        outcome: AuditOutcome,
        actor: ActorClass,
        revision: Option<u64>,
    },
}

impl EventData {
    pub fn target(self) -> &'static str {
        match self {
            Self::Access { .. } => "fluxheim::event::access",
            Self::Error { .. } => "fluxheim::event::error",
            Self::Security { .. } => "fluxheim::event::security",
            Self::Audit { .. } => "fluxheim::event::audit",
        }
    }

    pub fn kind(self) -> &'static str {
        match self {
            Self::Access { .. } => "access",
            Self::Error { .. } => "error",
            Self::Security { .. } => "security",
            Self::Audit { .. } => "audit",
        }
    }

    pub fn level(self) -> log::Level {
        match self {
            Self::Error { .. }
            | Self::Audit {
                outcome: AuditOutcome::Failed,
                ..
            } => log::Level::Error,
            Self::Security { .. }
            | Self::Audit {
                outcome: AuditOutcome::Rejected,
                ..
            } => log::Level::Warn,
            Self::Access { .. } | Self::Audit { .. } => log::Level::Info,
        }
    }

    pub fn message(self) -> &'static str {
        match self {
            Self::Access { .. } => "Request outcome",
            Self::Error { .. } => "Operation failed",
            Self::Security { .. } => "Security policy decision",
            Self::Audit { .. } => "Administrative operation outcome",
        }
    }

    pub fn admission_class(self) -> AdmissionClass {
        match self {
            Self::Security { .. } => AdmissionClass::Security,
            Self::Audit { .. } => AdmissionClass::Audit,
            Self::Access { .. } | Self::Error { .. } => AdmissionClass::Ordinary,
        }
    }
}

/// Independent admission and queue capacity; public traffic cannot spend audit capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdmissionClass {
    Ordinary,
    Security,
    Audit,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AccessOutcome {
    Completed,
    Cancelled,
    Failed,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FailureReason {
    Dns,
    ConnectionRefused,
    ConnectionTimeout,
    ReadTimeout,
    WriteTimeout,
    TlsVerification,
    TlsHandshake,
    UpstreamProtocol,
    CacheRead,
    CacheWrite,
    CacheEncryption,
    PhpConnect,
    PhpProtocol,
    PhpTimeout,
    WasmTrap,
    WasmTimeout,
    WasmExecution,
    Acme,
    Reload,
    Rollback,
    Telemetry,
    Internal,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityReason {
    AuthenticationRejected,
    AuthorizationRejected,
    HostRejected,
    RequestLimit,
    RateLimit,
    AdmissionRejected,
    PathRejected,
    WasmDenied,
    InvalidTraceContext,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOperation {
    Reload,
    Snapshot,
    Rollback,
    SelfHeal,
    CachePurge,
    CacheActivityReset,
    LoadBalancerUpdate,
    PersistenceClear,
    CertificateRenewal,
    CertificateRevocation,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditOutcome {
    Succeeded,
    Failed,
    Rejected,
}

/// An authentication class, never a claim to know which human used a shared token.
#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ActorClass {
    AdminToken,
    LocalOperations,
    Automatic,
}

#[derive(Debug, Clone, Copy, Serialize)]
pub enum Method {
    GET,
    HEAD,
    POST,
    PUT,
    PATCH,
    DELETE,
    OPTIONS,
    TRACE,
    CONNECT,
    OTHER,
}

impl Method {
    pub fn from_request(value: &str) -> Self {
        match value {
            "GET" => Self::GET,
            "HEAD" => Self::HEAD,
            "POST" => Self::POST,
            "PUT" => Self::PUT,
            "PATCH" => Self::PATCH,
            "DELETE" => Self::DELETE,
            "OPTIONS" => Self::OPTIONS,
            "TRACE" => Self::TRACE,
            "CONNECT" => Self::CONNECT,
            _ => Self::OTHER,
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(transparent)]
pub struct HttpStatus(u16);

impl HttpStatus {
    pub fn new(value: u16) -> Option<Self> {
        (100..=599).contains(&value).then_some(Self(value))
    }
}

/// A configured identity within a runtime generation, not a host, URL or backend address.
/// Producers must use configuration indices, never hashes of untrusted request data.
#[derive(Debug, Clone, Copy, Serialize)]
pub struct ResourceId {
    pub kind: ResourceKind,
    pub generation: u64,
    pub index: u32,
}

#[derive(Debug, Clone, Copy, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ResourceKind {
    Listener,
    Vhost,
    Route,
    Upstream,
    Cache,
    PhpPool,
    AcmeIssuer,
    WasmModule,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_fields_and_codes_are_stable() {
        for (data, expected) in [
            (
                EventData::Access {
                    outcome: AccessOutcome::Cancelled,
                    method: Method::GET,
                    status: None,
                    duration_micros: 12,
                    bytes_sent: 4,
                    attempts: 0,
                },
                serde_json::json!({"kind":"access", "outcome":"cancelled", "method":"GET",
                    "status":null, "duration_micros":12, "bytes_sent":4, "attempts":0}),
            ),
            (
                EventData::Error {
                    reason: FailureReason::TlsVerification,
                    attempt: Some(2),
                },
                serde_json::json!({"kind":"error", "reason":"tls_verification", "attempt":2}),
            ),
            (
                EventData::Security {
                    reason: SecurityReason::HostRejected,
                },
                serde_json::json!({"kind":"security", "reason":"host_rejected"}),
            ),
            (
                EventData::Audit {
                    operation: AuditOperation::CachePurge,
                    outcome: AuditOutcome::Succeeded,
                    actor: ActorClass::AdminToken,
                    revision: None,
                },
                serde_json::json!({"kind":"audit", "operation":"cache_purge", "outcome":"succeeded",
                    "actor":"admin_token", "revision":null}),
            ),
        ] {
            assert_eq!(serde_json::to_value(data).unwrap(), expected);
            assert_eq!(expected["kind"], data.kind());
        }
    }

    #[test]
    fn audit_severity_and_reservation_are_outcome_aware() {
        for (outcome, level) in [
            (AuditOutcome::Succeeded, log::Level::Info),
            (AuditOutcome::Rejected, log::Level::Warn),
            (AuditOutcome::Failed, log::Level::Error),
        ] {
            let data = EventData::Audit {
                operation: AuditOperation::Reload,
                outcome,
                actor: ActorClass::Automatic,
                revision: None,
            };
            assert_eq!(data.level(), level);
            assert_eq!(data.admission_class(), AdmissionClass::Audit);
        }
        assert_eq!(
            EventData::Error {
                reason: FailureReason::Internal,
                attempt: None
            }
            .admission_class(),
            AdmissionClass::Ordinary
        );
    }
}
