use super::*;

pub(super) fn order_error(error: io::Error) -> AcmeRenewalError {
    AcmeRenewalError::Challenge {
        token: String::new(),
        error: error.kind().into(),
    }
}

pub(super) fn finish_renewal_cleanup(
    result: Result<AcmeRenewalOutcome, AcmeRenewalError>,
    cleanup: Result<(), AcmeRenewalError>,
) -> Result<AcmeRenewalOutcome, AcmeRenewalError> {
    match (result, cleanup) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Err(error), Ok(())) => Err(error),
        (Ok(mut outcome), Err(_)) => {
            log::error!("ACME certificate installed; challenge cleanup pending");
            outcome.cleanup_pending = true;
            Ok(outcome)
        }
        (Err(error), Err(_)) => {
            log::error!(
                target: "fluxheim::security",
                "ACME challenge cleanup also failed after renewal failure"
            );
            Err(error)
        }
    }
}
