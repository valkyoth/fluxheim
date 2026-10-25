use super::*;

impl AccessOutcome {
    pub fn metric_label(self) -> &'static str {
        match self {
            Self::Completed => "completed",
            Self::Cancelled => "cancelled",
            Self::Failed => "failed",
        }
    }
}

impl FailureReason {
    pub fn metric_label(self) -> &'static str {
        match self {
            Self::Dns => "dns",
            Self::ConnectionRefused => "connection_refused",
            Self::ConnectionTimeout => "connection_timeout",
            Self::ReadTimeout => "read_timeout",
            Self::WriteTimeout => "write_timeout",
            Self::TlsVerification => "tls_verification",
            Self::TlsHandshake => "tls_handshake",
            Self::UpstreamProtocol => "upstream_protocol",
            Self::CacheRead => "cache_read",
            Self::CacheWrite => "cache_write",
            Self::CacheEncryption => "cache_encryption",
            Self::PhpConnect => "php_connect",
            Self::PhpProtocol => "php_protocol",
            Self::PhpTimeout => "php_timeout",
            Self::WasmTrap => "wasm_trap",
            Self::WasmTimeout => "wasm_timeout",
            Self::WasmExecution => "wasm_execution",
            Self::Acme => "acme",
            Self::Reload => "reload",
            Self::Rollback => "rollback",
            Self::Telemetry => "telemetry",
            Self::Internal => "internal",
        }
    }
}

impl SecurityReason {
    pub fn metric_label(self) -> &'static str {
        match self {
            Self::AuthenticationRejected => "authentication_rejected",
            Self::AuthorizationRejected => "authorization_rejected",
            Self::HostRejected => "host_rejected",
            Self::RequestLimit => "request_limit",
            Self::RateLimit => "rate_limit",
            Self::AdmissionRejected => "admission_rejected",
            Self::PathRejected => "path_rejected",
            Self::WasmDenied => "wasm_denied",
            Self::InvalidTraceContext => "invalid_trace_context",
        }
    }
}

impl AuditOperation {
    pub fn metric_label(self) -> &'static str {
        match self {
            Self::Reload => "reload",
            Self::Snapshot => "snapshot",
            Self::Rollback => "rollback",
            Self::SelfHeal => "self_heal",
            Self::CachePurge => "cache_purge",
            Self::CacheActivityReset => "cache_activity_reset",
            Self::LoadBalancerUpdate => "load_balancer_update",
            Self::PersistenceClear => "persistence_clear",
            Self::CertificateRenewal => "certificate_renewal",
            Self::CertificateRevocation => "certificate_revocation",
        }
    }
}

impl AuditOutcome {
    pub fn metric_label(self) -> &'static str {
        match self {
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Rejected => "rejected",
        }
    }
}

impl Method {
    pub fn metric_label(self) -> &'static str {
        match self {
            Self::GET => "GET",
            Self::HEAD => "HEAD",
            Self::POST => "POST",
            Self::PUT => "PUT",
            Self::PATCH => "PATCH",
            Self::DELETE => "DELETE",
            Self::OPTIONS => "OPTIONS",
            Self::TRACE => "TRACE",
            Self::CONNECT => "CONNECT",
            Self::OTHER => "OTHER",
        }
    }
}
