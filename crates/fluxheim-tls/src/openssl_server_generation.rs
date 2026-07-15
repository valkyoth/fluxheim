use std::sync::{Arc, Mutex, MutexGuard, Weak};

use openssl::ex_data::Index;
use openssl::ssl::{Ssl, SslRef};

use super::OpenSslDownstreamCertificateStoreError;

pub(super) struct OpenSslGenerationLease;

pub(super) struct OpenSslReloadGenerationState {
    live: Mutex<Vec<Weak<OpenSslGenerationLease>>>,
    lease_index: Index<Ssl, Arc<OpenSslGenerationLease>>,
}

impl OpenSslReloadGenerationState {
    pub(super) fn new(
        initial: &Arc<OpenSslGenerationLease>,
    ) -> Result<Self, OpenSslDownstreamCertificateStoreError> {
        let lease_index = Ssl::new_ex_index::<Arc<OpenSslGenerationLease>>()
            .map_err(OpenSslDownstreamCertificateStoreError::CreateGenerationLeaseIndex)?;
        Ok(Self {
            live: Mutex::new(vec![Arc::downgrade(initial)]),
            lease_index,
        })
    }

    pub(super) fn lock(
        &self,
        maximum: usize,
    ) -> Result<OpenSslReloadGenerationGuard<'_>, OpenSslDownstreamCertificateStoreError> {
        let mut live = self
            .live
            .lock()
            .map_err(|_| OpenSslDownstreamCertificateStoreError::ReloadGenerationStatePoisoned)?;
        live.retain(|generation| generation.strong_count() != 0);
        if live.len() >= maximum {
            return Err(
                OpenSslDownstreamCertificateStoreError::TooManyLiveGenerations {
                    count: live.len(),
                    maximum,
                },
            );
        }
        Ok(OpenSslReloadGenerationGuard { live })
    }

    pub(super) fn attach_to_ssl(&self, ssl: &mut SslRef, lease: Arc<OpenSslGenerationLease>) {
        ssl.set_ex_data(self.lease_index, lease);
    }
}

pub(super) struct OpenSslReloadGenerationGuard<'a> {
    live: MutexGuard<'a, Vec<Weak<OpenSslGenerationLease>>>,
}

impl OpenSslReloadGenerationGuard<'_> {
    pub(super) fn track(&mut self, lease: &Arc<OpenSslGenerationLease>) {
        self.live.push(Arc::downgrade(lease));
    }
}
