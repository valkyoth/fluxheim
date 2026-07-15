use std::sync::Arc;
use std::time::{Duration, Instant};

use super::client_auth::OpenSslClientAuthPolicy;
use super::{
    OPENSSL_RELOAD_POLICY_GENERATIONS, OpenSslCertificateGeneration,
    OpenSslDownstreamCertificateStore, OpenSslDownstreamCertificateStoreError,
    load_openssl_downstream_certificates, validate_openssl_sni_context_budget,
};

impl OpenSslDownstreamCertificateStore {
    pub fn reload(&self) -> Result<(), OpenSslDownstreamCertificateStoreError> {
        let _operation = self
            .reload_operation
            .lock()
            .map_err(|_| OpenSslDownstreamCertificateStoreError::ReloadOperationStatePoisoned)?;
        self.reload_once()
    }

    fn reload_once(&self) -> Result<(), OpenSslDownstreamCertificateStoreError> {
        let mut reload = self
            .reload_generations
            .lock(OPENSSL_RELOAD_POLICY_GENERATIONS)?;
        let client_auth = OpenSslClientAuthPolicy::load(&self.tls)?;
        validate_openssl_sni_context_budget(
            self.selector.certificates().len(),
            client_auth.input_bytes(),
        )?;
        let certificates = load_openssl_downstream_certificates(
            &self.selector,
            &self.tls,
            &client_auth,
            self.session_cache_entries_per_context,
            self.pending_managed_certificate_recorder,
        )?;
        let lease = self.reload_generations.new_lease();
        let generation = Arc::new(OpenSslCertificateGeneration {
            certificates,
            lease: lease.clone(),
        });
        reload.track(&lease);
        self.generation.store(generation);
        Ok(())
    }

    pub fn reload_after_generation_drain(
        &self,
        timeout: Duration,
    ) -> Result<(), OpenSslDownstreamCertificateStoreError> {
        let _operation = self
            .reload_operation
            .lock()
            .map_err(|_| OpenSslDownstreamCertificateStoreError::ReloadOperationStatePoisoned)?;
        let deadline = Instant::now()
            .checked_add(timeout)
            .unwrap_or_else(Instant::now);
        loop {
            match self.reload_once() {
                Ok(()) => return Ok(()),
                Err(
                    error @ OpenSslDownstreamCertificateStoreError::TooManyLiveGenerations {
                        ..
                    },
                ) => {
                    let remaining = deadline.saturating_duration_since(Instant::now());
                    if remaining.is_zero()
                        || !self
                            .reload_generations
                            .wait_for_capacity(OPENSSL_RELOAD_POLICY_GENERATIONS, remaining)?
                    {
                        return Err(error);
                    }
                }
                Err(error) => return Err(error),
            }
        }
    }
}
