use std::fmt;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const STATIC_RESPONSE_BUDGET_UNIT_BYTES: usize = 64 * 1024;
const MAX_BUFFERED_STATIC_RESPONSE_BYTES: usize = 256 * 1024 * 1024;
const STATIC_RESPONSE_ADMISSION_WAIT: Duration = Duration::from_millis(250);

static STATIC_RESPONSE_SLOTS: OnceLock<Arc<Semaphore>> = OnceLock::new();

#[derive(Clone)]
pub(crate) struct NativeResponseRetention {
    _permit: Arc<OwnedSemaphorePermit>,
}

impl fmt::Debug for NativeResponseRetention {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NativeResponseRetention")
    }
}

impl PartialEq for NativeResponseRetention {
    fn eq(&self, _other: &Self) -> bool {
        true
    }
}

impl Eq for NativeResponseRetention {}

pub(crate) async fn acquire_static_response_retention(
    bytes: usize,
) -> std::io::Result<NativeResponseRetention> {
    let slots = STATIC_RESPONSE_SLOTS
        .get_or_init(|| {
            Arc::new(Semaphore::new(
                MAX_BUFFERED_STATIC_RESPONSE_BYTES / STATIC_RESPONSE_BUDGET_UNIT_BYTES,
            ))
        })
        .clone();
    acquire_static_response_retention_from(slots, bytes).await
}

pub(crate) async fn acquire_static_response_retention_from(
    slots: Arc<Semaphore>,
    bytes: usize,
) -> std::io::Result<NativeResponseRetention> {
    let units = u32::try_from(bytes.div_ceil(STATIC_RESPONSE_BUDGET_UNIT_BYTES).max(1))
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::WouldBlock))?;
    tokio::time::timeout(
        STATIC_RESPONSE_ADMISSION_WAIT,
        slots.acquire_many_owned(units),
    )
    .await
    .map_err(|_| std::io::Error::from(std::io::ErrorKind::WouldBlock))?
    .map(|permit| NativeResponseRetention {
        _permit: Arc::new(permit),
    })
    .map_err(|_| std::io::Error::other("static response admission closed"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn static_response_slots_reject_overcommit_and_recover() {
        let slots = Arc::new(Semaphore::new(2));
        let first = acquire_static_response_retention_from(
            slots.clone(),
            STATIC_RESPONSE_BUDGET_UNIT_BYTES + 1,
        )
        .await
        .unwrap();
        assert_eq!(
            acquire_static_response_retention_from(slots.clone(), 1)
                .await
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::WouldBlock
        );
        drop(first);
        assert!(
            acquire_static_response_retention_from(slots, STATIC_RESPONSE_BUDGET_UNIT_BYTES)
                .await
                .is_ok()
        );
    }
}
