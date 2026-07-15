use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, OnceLock, Weak};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use openssl::ex_data::Index;
use openssl::ssl::{Ssl, SslRef};

use super::OpenSslDownstreamCertificateStoreError;

type OpenSslConnectionLeaseIndex = Index<Ssl, Arc<OpenSslConnectionLease>>;

static LEASE_INDEX: OnceLock<OpenSslConnectionLeaseIndex> = OnceLock::new();
static LEASE_INDEX_INITIALIZATION: Mutex<()> = Mutex::new(());

struct OpenSslGenerationRegistry {
    live: Mutex<Vec<Weak<OpenSslGenerationLease>>>,
    released: Condvar,
}

pub(super) struct OpenSslGenerationLease {
    drain_requested: AtomicBool,
    drain_registrations: Mutex<OpenSslDrainRegistrations>,
    registry: Weak<OpenSslGenerationRegistry>,
}

struct OpenSslDrainRegistrations {
    next_connection_id: u64,
    wakers: HashMap<u64, Waker>,
}

struct OpenSslConnectionLease {
    id: u64,
    generation: Arc<OpenSslGenerationLease>,
}

impl OpenSslGenerationLease {
    fn new(registry: &Arc<OpenSslGenerationRegistry>) -> Self {
        Self {
            drain_requested: AtomicBool::new(false),
            drain_registrations: Mutex::new(OpenSslDrainRegistrations {
                next_connection_id: 0,
                wakers: HashMap::new(),
            }),
            registry: Arc::downgrade(registry),
        }
    }

    fn new_connection(self: &Arc<Self>) -> OpenSslConnectionLease {
        let mut registrations = self
            .drain_registrations
            .lock()
            .unwrap_or_else(|_| abort_generation_waker_poison());
        let id = registrations.next_connection_id;
        registrations.next_connection_id = id
            .checked_add(1)
            .unwrap_or_else(|| abort_generation_connection_id_exhausted());
        OpenSslConnectionLease {
            id,
            generation: self.clone(),
        }
    }

    fn request_drain(&self) {
        self.drain_requested.store(true, Ordering::Release);
        let wakers = {
            let mut registrations = self
                .drain_registrations
                .lock()
                .unwrap_or_else(|_| abort_generation_waker_poison());
            std::mem::take(&mut registrations.wakers)
        };
        for (_, wake) in wakers {
            wake.wake();
        }
    }
}

impl OpenSslConnectionLease {
    fn poll_drain(&self, context: &mut Context<'_>) -> Poll<()> {
        if self.generation.drain_requested.load(Ordering::Acquire) {
            return Poll::Ready(());
        }
        let mut registered = self
            .generation
            .drain_registrations
            .lock()
            .unwrap_or_else(|_| abort_generation_waker_poison());
        if self.generation.drain_requested.load(Ordering::Acquire) {
            return Poll::Ready(());
        }
        if !registered
            .wakers
            .get(&self.id)
            .is_some_and(|registered| registered.will_wake(context.waker()))
        {
            registered.wakers.insert(self.id, context.waker().clone());
        }
        Poll::Pending
    }
}

impl Drop for OpenSslConnectionLease {
    fn drop(&mut self) {
        self.generation
            .drain_registrations
            .lock()
            .unwrap_or_else(|_| abort_generation_waker_poison())
            .wakers
            .remove(&self.id);
    }
}

impl Drop for OpenSslGenerationLease {
    fn drop(&mut self) {
        if let Some(registry) = self.registry.upgrade() {
            registry.released.notify_all();
        }
    }
}

pub(super) struct OpenSslReloadGenerationState {
    registry: Arc<OpenSslGenerationRegistry>,
}

impl OpenSslReloadGenerationState {
    pub(super) fn new()
    -> Result<(Self, Arc<OpenSslGenerationLease>), OpenSslDownstreamCertificateStoreError> {
        generation_lease_index()?;
        let registry = Arc::new(OpenSslGenerationRegistry {
            live: Mutex::new(Vec::new()),
            released: Condvar::new(),
        });
        let lease = Arc::new(OpenSslGenerationLease::new(&registry));
        registry
            .live
            .lock()
            .map_err(|_| OpenSslDownstreamCertificateStoreError::ReloadGenerationStatePoisoned)?
            .push(Arc::downgrade(&lease));
        Ok((Self { registry }, lease))
    }

    pub(super) fn new_lease(&self) -> Arc<OpenSslGenerationLease> {
        Arc::new(OpenSslGenerationLease::new(&self.registry))
    }

    pub(super) fn lock(
        &self,
        maximum: usize,
    ) -> Result<OpenSslReloadGenerationGuard<'_>, OpenSslDownstreamCertificateStoreError> {
        let mut live =
            self.registry.live.lock().map_err(|_| {
                OpenSslDownstreamCertificateStoreError::ReloadGenerationStatePoisoned
            })?;
        prune_released_generations(&mut live);
        if live.len() >= maximum {
            if let Some(oldest) = live.first().and_then(Weak::upgrade) {
                oldest.request_drain();
            }
            return Err(
                OpenSslDownstreamCertificateStoreError::TooManyLiveGenerations {
                    count: live.len(),
                    maximum,
                },
            );
        }
        Ok(OpenSslReloadGenerationGuard { live })
    }

    pub(super) fn wait_for_capacity(
        &self,
        maximum: usize,
        timeout: Duration,
    ) -> Result<bool, OpenSslDownstreamCertificateStoreError> {
        let live =
            self.registry.live.lock().map_err(|_| {
                OpenSslDownstreamCertificateStoreError::ReloadGenerationStatePoisoned
            })?;
        let (mut live, _) = self
            .registry
            .released
            .wait_timeout_while(live, timeout, |live| {
                prune_released_generations(live);
                live.len() >= maximum
            })
            .map_err(|_| OpenSslDownstreamCertificateStoreError::ReloadGenerationStatePoisoned)?;
        prune_released_generations(&mut live);
        Ok(live.len() < maximum)
    }

    pub(super) fn attach_to_ssl(
        &self,
        ssl: &mut SslRef,
        lease: Arc<OpenSslGenerationLease>,
    ) -> Result<(), OpenSslDownstreamCertificateStoreError> {
        let connection = Arc::new(lease.new_connection());
        let index = generation_lease_index()?;
        ssl.set_ex_data(index, connection);
        if ssl.ex_data(index).is_none() {
            abort_generation_lease_attachment_failure();
        }
        Ok(())
    }
}

pub(super) fn poll_connection_drain(ssl: &SslRef, context: &mut Context<'_>) -> Poll<()> {
    let Some(lease) = LEASE_INDEX.get().and_then(|index| ssl.ex_data(*index)) else {
        return Poll::Pending;
    };
    lease.poll_drain(context)
}

pub(super) struct OpenSslReloadGenerationGuard<'a> {
    live: MutexGuard<'a, Vec<Weak<OpenSslGenerationLease>>>,
}

impl OpenSslReloadGenerationGuard<'_> {
    pub(super) fn track(&mut self, lease: &Arc<OpenSslGenerationLease>) {
        self.live.push(Arc::downgrade(lease));
    }
}

fn generation_lease_index()
-> Result<OpenSslConnectionLeaseIndex, OpenSslDownstreamCertificateStoreError> {
    if let Some(index) = LEASE_INDEX.get() {
        return Ok(*index);
    }
    let _initialization = LEASE_INDEX_INITIALIZATION
        .lock()
        .map_err(|_| OpenSslDownstreamCertificateStoreError::GenerationLeaseIndexStatePoisoned)?;
    if let Some(index) = LEASE_INDEX.get() {
        return Ok(*index);
    }
    let created = Ssl::new_ex_index::<Arc<OpenSslConnectionLease>>()
        .map_err(OpenSslDownstreamCertificateStoreError::CreateGenerationLeaseIndex)?;
    LEASE_INDEX
        .set(created)
        .map_err(|_| OpenSslDownstreamCertificateStoreError::GenerationLeaseIndexInitialization)?;
    Ok(created)
}

fn prune_released_generations(live: &mut Vec<Weak<OpenSslGenerationLease>>) {
    live.retain(|generation| generation.strong_count() != 0);
}

fn abort_generation_waker_poison() -> ! {
    log::error!(target: "fluxheim::tls", "OpenSSL generation drain waker lock poisoned");
    std::process::abort()
}

fn abort_generation_connection_id_exhausted() -> ! {
    log::error!(target: "fluxheim::tls", "OpenSSL generation connection ID space exhausted");
    std::process::abort()
}

fn abort_generation_lease_attachment_failure() -> ! {
    log::error!(target: "fluxheim::tls", "OpenSSL connection generation lease attachment failed");
    std::process::abort()
}

#[cfg(test)]
mod tests {
    use super::generation_lease_index;

    #[test]
    fn generation_lease_index_is_process_global() {
        let first = generation_lease_index().unwrap();
        let second = generation_lease_index().unwrap();

        assert_eq!(first.as_raw(), second.as_raw());
    }
}
