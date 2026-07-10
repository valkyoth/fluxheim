use std::sync::{Arc, OnceLock};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const MAX_REQUEST_BLOCKING_WORK: usize = 256;
const MAX_NON_CRITICAL_BLOCKING_WORK: usize = 224;
const MAX_AUTH_BLOCKING_WORK: usize = 96;
#[cfg(any(test, feature = "wasm"))]
const MAX_WASM_BLOCKING_WORK: usize = 96;
const MAX_DISK_CACHE_BLOCKING_WORK: usize = 32;
#[cfg(any(test, all(feature = "traffic-mirror", not(feature = "privacy-mode"))))]
const MAX_MIRROR_BLOCKING_WORK: usize = 8;
const MAX_CRITICAL_BLOCKING_WORK: usize = 32;

static REQUEST_BLOCKING_WORK: OnceLock<NativeRequestBlockingWorkBudgets> = OnceLock::new();

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NativeBlockingWorkClass {
    Auth,
    #[cfg(any(test, feature = "wasm"))]
    Wasm,
    DiskCache,
    #[cfg(any(test, all(feature = "traffic-mirror", not(feature = "privacy-mode"))))]
    Mirror,
    Critical,
}

#[derive(Debug)]
pub(crate) struct NativeRequestBlockingWorkPermit {
    _class: OwnedSemaphorePermit,
    _non_critical: Option<OwnedSemaphorePermit>,
    _total: OwnedSemaphorePermit,
}

struct NativeRequestBlockingWorkBudgets {
    total: Arc<Semaphore>,
    non_critical: Arc<Semaphore>,
    auth: Arc<Semaphore>,
    #[cfg(any(test, feature = "wasm"))]
    wasm: Arc<Semaphore>,
    disk_cache: Arc<Semaphore>,
    #[cfg(any(test, all(feature = "traffic-mirror", not(feature = "privacy-mode"))))]
    mirror: Arc<Semaphore>,
    critical: Arc<Semaphore>,
}

impl NativeRequestBlockingWorkBudgets {
    fn production() -> Self {
        Self {
            total: Arc::new(Semaphore::new(MAX_REQUEST_BLOCKING_WORK)),
            non_critical: Arc::new(Semaphore::new(MAX_NON_CRITICAL_BLOCKING_WORK)),
            auth: Arc::new(Semaphore::new(MAX_AUTH_BLOCKING_WORK)),
            #[cfg(any(test, feature = "wasm"))]
            wasm: Arc::new(Semaphore::new(MAX_WASM_BLOCKING_WORK)),
            disk_cache: Arc::new(Semaphore::new(MAX_DISK_CACHE_BLOCKING_WORK)),
            #[cfg(any(test, all(feature = "traffic-mirror", not(feature = "privacy-mode"))))]
            mirror: Arc::new(Semaphore::new(MAX_MIRROR_BLOCKING_WORK)),
            critical: Arc::new(Semaphore::new(MAX_CRITICAL_BLOCKING_WORK)),
        }
    }

    fn class_budget(&self, class: NativeBlockingWorkClass) -> &Arc<Semaphore> {
        match class {
            NativeBlockingWorkClass::Auth => &self.auth,
            #[cfg(any(test, feature = "wasm"))]
            NativeBlockingWorkClass::Wasm => &self.wasm,
            NativeBlockingWorkClass::DiskCache => &self.disk_cache,
            #[cfg(any(test, all(feature = "traffic-mirror", not(feature = "privacy-mode"))))]
            NativeBlockingWorkClass::Mirror => &self.mirror,
            NativeBlockingWorkClass::Critical => &self.critical,
        }
    }

    fn try_acquire(
        &self,
        class: NativeBlockingWorkClass,
    ) -> std::io::Result<NativeRequestBlockingWorkPermit> {
        let class_permit = self
            .class_budget(class)
            .clone()
            .try_acquire_owned()
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::WouldBlock))?;
        let non_critical = if class == NativeBlockingWorkClass::Critical {
            None
        } else {
            Some(
                self.non_critical
                    .clone()
                    .try_acquire_owned()
                    .map_err(|_| std::io::Error::from(std::io::ErrorKind::WouldBlock))?,
            )
        };
        let total = self
            .total
            .clone()
            .try_acquire_owned()
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::WouldBlock))?;
        Ok(NativeRequestBlockingWorkPermit {
            _class: class_permit,
            _non_critical: non_critical,
            _total: total,
        })
    }
}

pub(crate) fn try_acquire_request_blocking_work(
    class: NativeBlockingWorkClass,
) -> std::io::Result<NativeRequestBlockingWorkPermit> {
    REQUEST_BLOCKING_WORK
        .get_or_init(NativeRequestBlockingWorkBudgets::production)
        .try_acquire(class)
}

#[cfg(test)]
pub(crate) fn exhaust_disk_cache_blocking_work_for_test() -> Vec<NativeRequestBlockingWorkPermit> {
    (0..MAX_DISK_CACHE_BLOCKING_WORK)
        .map(|_| try_acquire_request_blocking_work(NativeBlockingWorkClass::DiskCache).unwrap())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_class_cannot_consume_the_shared_blocking_budget() {
        let budgets = NativeRequestBlockingWorkBudgets::production();
        let permits = (0..MAX_AUTH_BLOCKING_WORK)
            .map(|_| budgets.try_acquire(NativeBlockingWorkClass::Auth).unwrap())
            .collect::<Vec<_>>();

        assert_eq!(
            budgets
                .try_acquire(NativeBlockingWorkClass::Auth)
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
        assert!(budgets.try_acquire(NativeBlockingWorkClass::Wasm).is_ok());
        assert!(
            budgets
                .try_acquire(NativeBlockingWorkClass::DiskCache)
                .is_ok()
        );
        assert!(
            budgets
                .try_acquire(NativeBlockingWorkClass::Critical)
                .is_ok()
        );
        drop(permits);
    }

    #[test]
    fn non_critical_work_cannot_consume_critical_reserve() {
        let budgets = NativeRequestBlockingWorkBudgets::production();
        let mut non_critical = Vec::new();
        non_critical.extend(
            (0..MAX_AUTH_BLOCKING_WORK)
                .map(|_| budgets.try_acquire(NativeBlockingWorkClass::Auth).unwrap()),
        );
        non_critical.extend(
            (0..MAX_WASM_BLOCKING_WORK)
                .map(|_| budgets.try_acquire(NativeBlockingWorkClass::Wasm).unwrap()),
        );
        non_critical.extend((0..MAX_DISK_CACHE_BLOCKING_WORK).map(|_| {
            budgets
                .try_acquire(NativeBlockingWorkClass::DiskCache)
                .unwrap()
        }));
        assert_eq!(non_critical.len(), MAX_NON_CRITICAL_BLOCKING_WORK);
        assert!(
            budgets
                .try_acquire(NativeBlockingWorkClass::Mirror)
                .is_err()
        );

        let critical = (0..MAX_CRITICAL_BLOCKING_WORK)
            .map(|_| {
                budgets
                    .try_acquire(NativeBlockingWorkClass::Critical)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        assert_eq!(critical.len(), MAX_CRITICAL_BLOCKING_WORK);
        assert!(
            budgets
                .try_acquire(NativeBlockingWorkClass::Critical)
                .is_err()
        );
    }
}
