#[derive(Clone, Copy, Debug, Default, Eq, Ord, PartialEq, PartialOrd)]
pub struct PolicyEpoch(u64);

impl PolicyEpoch {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn value(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeFactVisibility {
    Public,
    Sensitive,
    SecretInternal,
}

impl RuntimeFactVisibility {
    pub const fn can_export_to_logs(self) -> bool {
        matches!(self, Self::Public)
    }

    pub const fn can_export_to_admin(self) -> bool {
        matches!(self, Self::Public | Self::Sensitive)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeFactKind {
    ConfigCandidateLoaded,
    ConfigReloadPromoted,
    RouteMatched,
    RouteAccessPolicyDenied,
    GeoContextUnavailable,
    AuthRequestDecided,
    RateLimitDecided,
    LoadBalancerBackendSelected,
    BackendEjected,
    BackendRestored,
    CacheObjectDecided,
    CacheObjectPurged,
    AcmeCertificateInstalled,
    AcmeRollbackAttempted,
    AdminMutationDecided,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeDecision {
    Allow,
    Deny,
    Redact,
    Defer,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeDecisionKind {
    AccessPolicy,
    AdminMutation,
    AuthRequest,
    CacheAdmission,
    ConfigPromotion,
    GeoPolicy,
    LoadBalancerSelection,
    RateLimit,
    RuntimeRecovery,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RuntimeDecisionReason {
    Accepted,
    Authenticated,
    BackendUnavailable,
    CacheBypass,
    CacheEligible,
    ConfigRejected,
    ContextUnavailable,
    DenyRuleMatched,
    InvalidInput,
    LimitExceeded,
    NotConfigured,
    PolicyDisabled,
    RequiredCredentialMissing,
    RuntimeError,
    UnsafePath,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PolicyProof {
    decision: RuntimeDecision,
    kind: RuntimeDecisionKind,
    reason: RuntimeDecisionReason,
    epoch: PolicyEpoch,
    input_count: u16,
    visibility: RuntimeFactVisibility,
}

impl PolicyProof {
    pub const fn new(
        decision: RuntimeDecision,
        kind: RuntimeDecisionKind,
        reason: RuntimeDecisionReason,
        epoch: PolicyEpoch,
    ) -> Self {
        Self {
            decision,
            kind,
            reason,
            epoch,
            input_count: 0,
            visibility: RuntimeFactVisibility::Public,
        }
    }

    pub const fn with_visibility(mut self, visibility: RuntimeFactVisibility) -> Self {
        self.visibility = visibility;
        self
    }

    pub fn with_input_count(mut self, input_count: usize) -> Self {
        self.input_count = input_count.min(u16::MAX as usize) as u16;
        self
    }

    pub const fn decision(self) -> RuntimeDecision {
        self.decision
    }

    pub const fn kind(self) -> RuntimeDecisionKind {
        self.kind
    }

    pub const fn reason(self) -> RuntimeDecisionReason {
        self.reason
    }

    pub const fn epoch(self) -> PolicyEpoch {
        self.epoch
    }

    pub const fn input_count(self) -> u16 {
        self.input_count
    }

    pub const fn visibility(self) -> RuntimeFactVisibility {
        self.visibility
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RuntimeFact {
    kind: RuntimeFactKind,
    epoch: PolicyEpoch,
    reason: RuntimeDecisionReason,
    visibility: RuntimeFactVisibility,
}

impl RuntimeFact {
    pub const fn new(
        kind: RuntimeFactKind,
        epoch: PolicyEpoch,
        reason: RuntimeDecisionReason,
    ) -> Self {
        Self {
            kind,
            epoch,
            reason,
            visibility: RuntimeFactVisibility::Public,
        }
    }

    pub const fn with_visibility(mut self, visibility: RuntimeFactVisibility) -> Self {
        self.visibility = visibility;
        self
    }

    pub const fn kind(self) -> RuntimeFactKind {
        self.kind
    }

    pub const fn epoch(self) -> PolicyEpoch {
        self.epoch
    }

    pub const fn reason(self) -> RuntimeDecisionReason {
        self.reason
    }

    pub const fn visibility(self) -> RuntimeFactVisibility {
        self.visibility
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_epoch_exposes_monotonic_value() {
        assert!(PolicyEpoch::new(8) > PolicyEpoch::new(7));
        assert_eq!(PolicyEpoch::new(42).value(), 42);
    }

    #[test]
    fn policy_proof_is_bounded_and_typed() {
        let proof = PolicyProof::new(
            RuntimeDecision::Deny,
            RuntimeDecisionKind::RateLimit,
            RuntimeDecisionReason::LimitExceeded,
            PolicyEpoch::new(5),
        )
        .with_input_count(usize::MAX)
        .with_visibility(RuntimeFactVisibility::Sensitive);

        assert_eq!(proof.decision(), RuntimeDecision::Deny);
        assert_eq!(proof.kind(), RuntimeDecisionKind::RateLimit);
        assert_eq!(proof.reason(), RuntimeDecisionReason::LimitExceeded);
        assert_eq!(proof.epoch(), PolicyEpoch::new(5));
        assert_eq!(proof.input_count(), u16::MAX);
        assert_eq!(proof.visibility(), RuntimeFactVisibility::Sensitive);
    }

    #[test]
    fn visibility_limits_default_exports() {
        assert!(RuntimeFactVisibility::Public.can_export_to_logs());
        assert!(RuntimeFactVisibility::Sensitive.can_export_to_admin());
        assert!(!RuntimeFactVisibility::Sensitive.can_export_to_logs());
        assert!(!RuntimeFactVisibility::SecretInternal.can_export_to_admin());
    }

    #[test]
    fn runtime_fact_preserves_epoch_reason_and_visibility() {
        let fact = RuntimeFact::new(
            RuntimeFactKind::BackendEjected,
            PolicyEpoch::new(9),
            RuntimeDecisionReason::BackendUnavailable,
        )
        .with_visibility(RuntimeFactVisibility::Sensitive);

        assert_eq!(fact.kind(), RuntimeFactKind::BackendEjected);
        assert_eq!(fact.epoch(), PolicyEpoch::new(9));
        assert_eq!(fact.reason(), RuntimeDecisionReason::BackendUnavailable);
        assert_eq!(fact.visibility(), RuntimeFactVisibility::Sensitive);
    }
}
