use std::io;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const BODY_BUDGET_UNIT_BYTES: usize = 64 * 1024;
const BODY_BUDGET_WAIT: Duration = Duration::from_millis(250);
const DEFAULT_PROCESS_BODY_BUDGET_BYTES: usize = 1024 * 1024 * 1024;

static DEFAULT_PROCESS_BODY_BUDGET: OnceLock<NativeRequestBodyBudget> = OnceLock::new();

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

    pub(crate) fn reservation(&self) -> NativeRequestBodyReservation {
        NativeRequestBodyReservation {
            budget: self.clone(),
            reserved_units: 0,
            permits: Vec::new(),
        }
    }

    pub(crate) async fn reserve(&self, bytes: usize) -> io::Result<NativeRequestBodyReservation> {
        let mut reservation = self.reservation();
        reservation.grow_to(bytes).await?;
        Ok(reservation)
    }

    fn default_process() -> Self {
        DEFAULT_PROCESS_BODY_BUDGET
            .get_or_init(|| Self::new(DEFAULT_PROCESS_BODY_BUDGET_BYTES))
            .clone()
    }
}

impl Default for NativeRequestBodyBudget {
    fn default() -> Self {
        Self::default_process()
    }
}

#[derive(Debug)]
pub(crate) struct NativeRequestBodyReservation {
    budget: NativeRequestBodyBudget,
    reserved_units: u32,
    permits: Vec<OwnedSemaphorePermit>,
}

impl NativeRequestBodyReservation {
    pub(crate) async fn grow_to(&mut self, bytes: usize) -> io::Result<()> {
        if bytes > self.budget.max_bytes {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let required_units = u32::try_from(bytes.div_ceil(BODY_BUDGET_UNIT_BYTES))
            .map_err(|_| io::Error::other("request body reservation overflow"))?;
        let additional_units = required_units.saturating_sub(self.reserved_units);
        if additional_units == 0 {
            return Ok(());
        }
        let permit = tokio::time::timeout(
            BODY_BUDGET_WAIT,
            self.budget
                .semaphore
                .clone()
                .acquire_many_owned(additional_units),
        )
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?
        .map_err(|_| io::Error::other("request body budget closed"))?;
        self.permits.push(permit);
        self.reserved_units = required_units;
        Ok(())
    }

    pub(crate) async fn reserve_overlap(
        &self,
        total_bytes: usize,
    ) -> io::Result<Option<OwnedSemaphorePermit>> {
        if total_bytes > self.budget.max_bytes {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let required_units = u32::try_from(total_bytes.div_ceil(BODY_BUDGET_UNIT_BYTES))
            .map_err(|_| io::Error::other("request body overlap reservation overflow"))?;
        let additional_units = required_units.saturating_sub(self.reserved_units);
        if additional_units == 0 {
            return Ok(None);
        }
        let permit = tokio::time::timeout(
            BODY_BUDGET_WAIT,
            self.budget
                .semaphore
                .clone()
                .acquire_many_owned(additional_units),
        )
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?
        .map_err(|_| io::Error::other("request body budget closed"))?;
        Ok(Some(permit))
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

    #[tokio::test]
    async fn incremental_reservation_charges_only_growth() {
        let budget = NativeRequestBodyBudget::new(BODY_BUDGET_UNIT_BYTES * 2);
        let mut first = budget.reservation();
        first.grow_to(1).await.unwrap();
        first.grow_to(BODY_BUDGET_UNIT_BYTES).await.unwrap();
        let second = budget.reserve(1).await.unwrap();

        assert!(first.grow_to(BODY_BUDGET_UNIT_BYTES + 1).await.is_err());
        drop(second);
        first.grow_to(BODY_BUDGET_UNIT_BYTES + 1).await.unwrap();
    }

    #[tokio::test]
    async fn temporary_overlap_is_charged_until_secure_reallocation_finishes() {
        let budget = NativeRequestBodyBudget::new(BODY_BUDGET_UNIT_BYTES * 2);
        let reservation = budget.reserve(BODY_BUDGET_UNIT_BYTES).await.unwrap();
        let overlap = reservation
            .reserve_overlap(BODY_BUDGET_UNIT_BYTES * 2)
            .await
            .unwrap();

        assert!(budget.reserve(1).await.is_err());
        drop(overlap);
        assert!(budget.reserve(1).await.is_ok());
    }

    #[test]
    fn default_api_budget_is_shared_process_wide() {
        let first = NativeRequestBodyBudget::default();
        let second = NativeRequestBodyBudget::default();

        assert!(Arc::ptr_eq(&first.semaphore, &second.semaphore));
        assert_eq!(first.max_bytes, DEFAULT_PROCESS_BODY_BUDGET_BYTES);
    }
}
