use std::sync::{Arc, OnceLock};

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

pub(crate) const MAX_REQUEST_BLOCKING_WORK: usize = 256;

static REQUEST_BLOCKING_WORK: OnceLock<NativeRequestBlockingWorkBudget> = OnceLock::new();

struct NativeRequestBlockingWorkBudget {
    semaphore: Arc<Semaphore>,
}

impl NativeRequestBlockingWorkBudget {
    fn new(capacity: usize) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(capacity)),
        }
    }

    fn try_acquire(&self) -> std::io::Result<OwnedSemaphorePermit> {
        self.semaphore
            .clone()
            .try_acquire_owned()
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::WouldBlock))
    }
}

pub(crate) fn try_acquire_request_blocking_work() -> std::io::Result<OwnedSemaphorePermit> {
    REQUEST_BLOCKING_WORK
        .get_or_init(|| NativeRequestBlockingWorkBudget::new(MAX_REQUEST_BLOCKING_WORK))
        .try_acquire()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_blocking_work_budget_is_bounded() {
        let budget = NativeRequestBlockingWorkBudget::new(2);
        let permits = (0..2)
            .map(|_| budget.try_acquire().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(
            budget.try_acquire().unwrap_err().kind(),
            std::io::ErrorKind::WouldBlock
        );
        drop(permits);
        assert!(budget.try_acquire().is_ok());
    }
}
