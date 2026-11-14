use std::collections::BTreeMap;
use std::io;
use std::sync::{Arc, Mutex};

#[derive(Debug)]
pub(crate) struct BinAdmission {
    limit: usize,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    active: usize,
    bins: BTreeMap<u64, usize>,
}

#[derive(Debug)]
pub(crate) struct BinPermit {
    admission: Arc<BinAdmission>,
    bin_id: u64,
}

impl BinAdmission {
    pub(crate) fn new(limit: usize) -> Arc<Self> {
        Arc::new(Self {
            limit,
            state: Mutex::new(State::default()),
        })
    }

    pub(crate) fn reserve(self: &Arc<Self>, bin_id: u64, removing: bool) -> io::Result<BinPermit> {
        if self.limit == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "storage-bin open limit must be nonzero",
            ));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| io::Error::other("storage-bin admission poisoned"))?;
        // A zero per-bin count denotes exclusive deletion, not an idle handle.
        if state.active >= self.limit
            || state
                .bins
                .get(&bin_id)
                .is_some_and(|count| removing || *count == 0)
        {
            return Err(busy());
        }
        let active = state.active.checked_add(1).ok_or_else(busy)?;
        let count = if removing {
            0
        } else {
            state
                .bins
                .get(&bin_id)
                .copied()
                .unwrap_or(0)
                .checked_add(1)
                .ok_or_else(busy)?
        };
        state.bins.insert(bin_id, count);
        state.active = active;
        Ok(BinPermit {
            admission: Arc::clone(self),
            bin_id,
        })
    }
}

impl Drop for BinPermit {
    fn drop(&mut self) {
        // No filesystem operation runs while this bookkeeping lock is held.
        let mut state = self
            .admission
            .state
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        state.active = state.active.saturating_sub(1);
        if let Some(count) = state.bins.get_mut(&self.bin_id) {
            if *count <= 1 {
                state.bins.remove(&self.bin_id);
            } else {
                *count -= 1;
            }
        }
    }
}

fn busy() -> io::Error {
    io::Error::new(
        io::ErrorKind::WouldBlock,
        "storage-bin file admission is busy",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn poisoned_bin_admission_rejects_new_work_but_releases_owned_permits() {
        let admission = BinAdmission::new(1);
        let permit = admission.reserve(0, false).unwrap();
        let _ = std::panic::catch_unwind(|| {
            let _state = admission.state.lock().unwrap();
            panic!("inject bookkeeping poison");
        });
        drop(permit);
        assert_eq!(admission.state.lock().unwrap_err().into_inner().active, 0);
        assert!(admission.reserve(0, false).is_err());
        assert!(admission.reserve(0, true).is_err());
    }
}
