use fluxheim_common::{FluxError, FluxResult};

use super::backend::BackendIdentity;
use super::key::backend_key;
use super::selection_hash::{FNV_OFFSET_BASIS, fnv1a64_with_seed, maglev_route_secret};

const MAGLEV_TABLE_SIZE: usize = 65_537;

#[derive(Clone, Debug)]
pub(super) struct MaglevTable {
    slots: Vec<u64>,
}

impl MaglevTable {
    pub(super) fn from_backend_identities<'a, I, B>(backends: I) -> FluxResult<Self>
    where
        I: IntoIterator<Item = &'a B>,
        B: BackendIdentity + 'a,
    {
        let keys: Vec<u64> = backends.into_iter().map(backend_key).collect();
        Self::from_backend_keys(&keys)
    }

    fn from_backend_keys(keys: &[u64]) -> FluxResult<Self> {
        if keys.is_empty() {
            return Err(FluxError::InvalidInput(
                "maglev requires at least one backend",
            ));
        }

        let mut slots = vec![u64::MAX; MAGLEV_TABLE_SIZE];
        let mut next = vec![0usize; keys.len()];
        let permutations: Vec<(usize, usize)> = keys
            .iter()
            .map(|backend_key| {
                let key = backend_key.to_le_bytes();
                let offset = fnv1a64_with_seed(&key, FNV_OFFSET_BASIS) as usize % MAGLEV_TABLE_SIZE;
                let skip = (fnv1a64_with_seed(&key, 0x8422_2325_cbf2_9ce4) as usize
                    % (MAGLEV_TABLE_SIZE - 1))
                    + 1;
                (offset, skip)
            })
            .collect();

        let mut filled = 0usize;
        while filled < MAGLEV_TABLE_SIZE {
            for (index, backend_key) in keys.iter().enumerate() {
                loop {
                    let (offset, skip) = permutations[index];
                    let candidate = maglev_candidate(offset, next[index], skip);
                    next[index] = next[index].saturating_add(1);
                    if slots[candidate] == u64::MAX {
                        slots[candidate] = *backend_key;
                        filled = filled.saturating_add(1);
                        break;
                    }
                }
                if filled == MAGLEV_TABLE_SIZE {
                    break;
                }
            }
        }

        Ok(Self { slots })
    }

    pub(super) fn candidate_keys<'a>(
        &'a self,
        key: &'a [u8],
        max_iterations: usize,
    ) -> impl Iterator<Item = u64> + 'a {
        let start = fnv1a64_with_seed(key, maglev_route_secret()) as usize % self.slots.len();
        let limit = max_iterations.max(1).min(self.slots.len());
        (0..limit).map(move |offset| self.slots[(start + offset) % self.slots.len()])
    }
}

pub(super) fn maglev_candidate(offset: usize, next: usize, skip: usize) -> usize {
    ((offset as u128 + (next as u128 * skip as u128)) % MAGLEV_TABLE_SIZE as u128) as usize
}

#[cfg(test)]
pub(super) fn maglev_table_size() -> usize {
    MAGLEV_TABLE_SIZE
}
