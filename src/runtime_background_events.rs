use fluxheim_observability::{
    event::{ActorClass, AuditOperation, AuditOutcome, FailureReason},
    operational::{audit, failure},
};

pub(super) fn renewal_outcome(succeeded: bool) {
    outcome(
        AuditOperation::CertificateRenewal,
        FailureReason::Acme,
        succeeded,
    );
}

pub(super) fn reload_outcome(succeeded: bool) {
    outcome(AuditOperation::Reload, FailureReason::Reload, succeeded);
}

fn outcome(operation: AuditOperation, reason: FailureReason, succeeded: bool) {
    if !succeeded {
        failure(reason);
    }
    audit(
        operation,
        if succeeded {
            AuditOutcome::Succeeded
        } else {
            AuditOutcome::Failed
        },
        ActorClass::Automatic,
    );
}

#[cfg(test)]
mod tests {
    #[test]
    fn background_outcomes_are_automatic_and_bounded() {
        let capture = fluxheim_observability::event_test_support::Capture::start();
        super::renewal_outcome(true);
        super::renewal_outcome(false);
        super::reload_outcome(true);
        super::reload_outcome(false);
        capture.assert_reason("acme", 1);
        capture.assert_reason("reload", 1);
        for operation in ["certificate_renewal", "reload"] {
            capture.assert_audit(operation, "succeeded", "automatic");
            capture.assert_audit(operation, "failed", "automatic");
        }
        assert_eq!(capture.events().len(), 6);
    }
}
