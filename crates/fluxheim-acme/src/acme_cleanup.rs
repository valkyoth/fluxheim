use super::*;

pub(super) fn finish_renewal_cleanup<T>(
    result: Result<T, AcmeRenewalError>,
    cleanup: Result<(), AcmeRenewalError>,
) -> Result<T, AcmeRenewalError> {
    match (result, cleanup) {
        (Ok(outcome), Ok(())) => Ok(outcome),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
        (Err(error), Err(cleanup_error)) => {
            log::error!(
                target: "fluxheim::security",
                "ACME challenge cleanup also failed after renewal failure: {cleanup_error}"
            );
            Err(error)
        }
    }
}
