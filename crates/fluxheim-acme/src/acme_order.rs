use super::*;
use acme_order_slot::{Kind, Slot};
use std::sync::{
    OnceLock,
    atomic::{AtomicUsize, Ordering},
    mpsc::{SyncSender, sync_channel},
};

const MAX_ORDERS: usize = 32;
static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);
static CLEANER: OnceLock<io::Result<SyncSender<Job>>> = OnceLock::new();

struct Job {
    slots: Vec<Slot>,
}

impl Drop for Job {
    fn drop(&mut self) {
        IN_FLIGHT.fetch_sub(1, Ordering::Release);
    }
}

impl Job {
    fn deactivate(&mut self) {
        for slot in &mut self.slots {
            slot.deactivate();
        }
    }
    fn clean(mut self) -> io::Result<()> {
        self.deactivate();
        let mut first = None;
        for slot in &self.slots {
            if let Err(e) = slot.retire() {
                first.get_or_insert(e);
            }
        }
        first.map_or(Ok(()), Err)
    }
}

pub(super) struct Order {
    job: Option<Job>,
    sender: &'static SyncSender<Job>,
}

impl Order {
    pub(super) fn new() -> io::Result<Self> {
        let sender = CLEANER
            .get_or_init(|| {
                let (tx, rx) = sync_channel::<Job>(MAX_ORDERS);
                std::thread::Builder::new()
                    .name("acme-cleanup".into())
                    .spawn(move || {
                        for job in rx {
                            if job.clean().is_err() {
                                log::error!(
                                    "ACME challenge cleanup incomplete; retained for reconciliation"
                                );
                            }
                        }
                    })?;
                Ok(tx)
            })
            .as_ref()
            .map_err(|e| io::Error::from(e.kind()))?;
        IN_FLIGHT
            .try_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                (n < MAX_ORDERS).then(|| n + 1)
            })
            .map_err(|_| io::ErrorKind::WouldBlock)?;
        Ok(Self {
            job: Some(Job { slots: Vec::new() }),
            sender,
        })
    }

    fn slots(&mut self) -> io::Result<&mut Vec<Slot>> {
        self.job
            .as_mut()
            .map(|job| &mut job.slots)
            .ok_or(io::ErrorKind::InvalidInput.into())
    }

    pub(super) fn http(
        &mut self,
        storage: &Path,
        vhost: &str,
        token: &str,
        value: &str,
    ) -> io::Result<()> {
        let slots = self.slots()?;
        if slots.is_empty() {
            let parent = AcmeHttp01ChallengeStore::new(storage, vhost).root;
            slots.push(
                Slot::open(storage, &parent, Kind::Http, true)?.ok_or(io::ErrorKind::WouldBlock)?,
            );
        }
        slots
            .first_mut()
            .ok_or(io::ErrorKind::InvalidData)?
            .publish_http(token, value)
    }

    #[cfg(all(test, feature = "acme-client"))]
    pub(super) fn alpn(
        &mut self,
        storage: &Path,
        domain: &str,
        cert: &[u8],
        key: &[u8],
    ) -> io::Result<()> {
        let slots = self.slots()?;
        if slots.len() >= acme_order_slot::MAX {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let parent = alpn_parent(storage, domain)?;
        slots.push(
            Slot::open(storage, &parent, Kind::Alpn, true)?.ok_or(io::ErrorKind::WouldBlock)?,
        );
        slots
            .last_mut()
            .ok_or(io::ErrorKind::InvalidData)?
            .publish_pair(domain, cert, key)
    }

    pub(super) fn finish(mut self) -> io::Result<()> {
        self.job.take().ok_or(io::ErrorKind::InvalidData)?.clean()
    }
}

impl Drop for Order {
    fn drop(&mut self) {
        if let Some(mut job) = self.job.take() {
            // Release serving leases now. Never wait on a file mutation or a
            // worker here. Each admitted job reserved a place in the queue.
            job.deactivate();
            let _ = self.sender.try_send(job);
        }
    }
}

fn alpn_parent(storage: &Path, domain: &str) -> io::Result<PathBuf> {
    let name = fluxheim_config::normalize_host(domain).ok_or(io::ErrorKind::InvalidInput)?;
    Ok(storage
        .join(TLS_ALPN_01_CHALLENGE_DIR)
        .join(managed_certificate_segment(&name)))
}

/// Recover only reserved namespaces of configured targets; never adopt legacy
/// files. A live competing publisher retains its exclusive lease.
pub fn reconcile_managed_challenges(config: &Config) -> io::Result<()> {
    let Some(storage) = config.tls.acme.storage.as_deref() else {
        return Ok(());
    };
    let mut first = None;
    for target in managed_acme_targets(config) {
        let http = AcmeHttp01ChallengeStore::new(storage, &target.vhost_name);
        if let Err(e) = Slot::open(storage, &http.root, Kind::Http, false) {
            first.get_or_insert(e);
        }
        for domain in target.domains {
            if let Err(e) = alpn_parent(storage, &domain)
                .and_then(|p| Slot::open(storage, &p, Kind::Alpn, false))
            {
                first.get_or_insert(e);
            }
        }
    }
    first.map_or(Ok(()), Err)
}
