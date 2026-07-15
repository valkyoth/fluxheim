use std::io;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const BODY_BUDGET_UNIT_BYTES: usize = 64 * 1024;
const BODY_BUDGET_WAIT: Duration = Duration::from_millis(250);

#[derive(Clone, Debug)]
pub struct NativeRequestBodyBudget {
    semaphore: Arc<Semaphore>,
    max_bytes: usize,
}

impl NativeRequestBodyBudget {
    pub fn new(max_bytes: usize) -> Self {
        let units = max_bytes
            .div_ceil(BODY_BUDGET_UNIT_BYTES)
            .clamp(1, u32::MAX as usize);
        Self {
            semaphore: Arc::new(Semaphore::new(units)),
            max_bytes,
        }
    }

    pub async fn reserve(&self, bytes: usize) -> io::Result<Option<OwnedSemaphorePermit>> {
        if bytes == 0 {
            return Ok(None);
        }
        if bytes > self.max_bytes {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let units = u32::try_from(bytes.div_ceil(BODY_BUDGET_UNIT_BYTES))
            .map_err(|_| io::Error::other("request body reservation overflow"))?;
        tokio::time::timeout(
            BODY_BUDGET_WAIT,
            self.semaphore.clone().acquire_many_owned(units),
        )
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?
        .map(Some)
        .map_err(|_| io::Error::other("request body budget closed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn weighted_budget_rejects_aggregate_overcommit_and_recovers() {
        let budget = NativeRequestBodyBudget::new(BODY_BUDGET_UNIT_BYTES * 2);
        let first = budget.reserve(BODY_BUDGET_UNIT_BYTES + 1).await.unwrap();

        assert_eq!(
            budget
                .reserve(BODY_BUDGET_UNIT_BYTES)
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        drop(first);
        assert!(budget.reserve(BODY_BUDGET_UNIT_BYTES).await.is_ok());
    }
}
